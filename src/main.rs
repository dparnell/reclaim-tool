mod reclaim;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use dirs::config_dir;
use mqtt_endpoint_tokio::mqtt_ep as mqtt;
use std::fs;
use std::io::Write;
use std::ops::Shr;
use std::path::{Path, PathBuf};
use aws_config::BehaviorVersion;
use tokio::net::lookup_host;

fn region_from_endpoint(endpoint: &str) -> Option<String> {
    // Expected formats:
    //  - <id>-ats.iot.<region>.amazonaws.com
    //  - <id>.iot.<region>.amazonaws.com
    let parts: Vec<&str> = endpoint.split('.').collect();
    // Find the "iot" label and take the next part as region
    if let Some(iot_idx) = parts.iter().position(|p| *p == "iot") {
        if let Some(region_part) = parts.get(iot_idx + 1) {
            return Some((*region_part).to_string());
        }
    }
    None
}

#[derive(Parser, Debug)]
#[command(name = "reclaim", version, about = "AWS IoT client for Reclaim Energy heat pump controller")] 
struct Cli {
    /// AWS region (e.g. ap-southeast-2)
    #[arg(long, global = true, default_value = reclaim::DEFAULT_AWS_REGION)]
    region: String,

    /// AWS IoT ATS endpoint hostname
    #[arg(long, global = true, default_value = reclaim::DEFAULT_AWS_ENDPOINT)]
    endpoint: String,

    /// Cognito Identity Pool ID
    #[arg(long, global = true, default_value = reclaim::DEFAULT_AWS_IDENTITY_POOL)]
    identity_pool_id: String,

    /// Configuration directory (defaults to ~/.config/reclaim)
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Fetch a new private key and certificate and save them to the config directory
    FetchCerts,

    /// Subscribe to dontek{hexid}/status/psw and print incoming messages
    Subscribe {
        /// The 17-digit unique decimal ID of the Reclaim Energy unit
        #[arg(long, value_name = "DECIMAL_ID")] 
        unique_id: String,
    },
}

fn config_home(cli: &Cli) -> Result<PathBuf> {
    if let Some(p) = &cli.config_dir {
        return Ok(p.clone());
    }
    let base = config_dir().ok_or_else(|| anyhow!("Could not resolve user config directory"))?;
    Ok(base.join("reclaim"))
}

fn ensure_ca_pem(path: &Path) -> Result<PathBuf> {
    let ca_path = path.join("AmazonRootCA1.pem");
    if ca_path.exists() {
        return Ok(ca_path);
    }
    fs::create_dir_all(path).context("creating config dir for CA")?;
    let url = "https://www.amazontrust.com/repository/AmazonRootCA1.pem";
    let response = ureq::get(url)
        .call()
        .map_err(|e| anyhow!("downloading Amazon Root CA 1: {}", e))?;
    let pem = response
        .into_string()
        .map_err(|e| anyhow!("reading CA body: {}", e))?;
    let mut f = fs::File::create(&ca_path).context("creating CA pem file")?;
    f.write_all(pem.as_bytes()).context("writing CA pem")?;
    Ok(ca_path)
}

async fn fetch_and_save_certs(cli: &Cli) -> Result<()> {
    use aws_config::Region;
    use aws_credential_types::Credentials;
    use aws_sdk_cognitoidentity as cognito;
    use aws_sdk_iot as iot;

    // Derive region from endpoint to avoid creating certs in the wrong region
    let ep_region = region_from_endpoint(&cli.endpoint);
    let chosen_region = ep_region.as_deref().unwrap_or(&cli.region);
    if let Some(ep) = &ep_region {
        if ep != &cli.region {
            eprintln!(
                "Warning: endpoint region '{}' differs from configured region '{}'; using endpoint region",
                ep, cli.region
            );
        }
    }
    let region = Region::new(chosen_region.to_string());

    // 1) Acquire unauthenticated Cognito Identity and temporary credentials
    let cognito_config = aws_config::defaults(BehaviorVersion::latest()).region(region.clone()).load().await;
    let cognito_client = cognito::Client::new(&cognito_config);

    let get_id_out = cognito_client
        .get_id()
        .identity_pool_id(cli.identity_pool_id.clone())
        .send()
        .await
        .context("CognitoIdentity GetId failed")?;
    let identity_id = get_id_out
        .identity_id()
        .ok_or_else(|| anyhow!("CognitoIdentity GetId returned no identity_id"))?
        .to_string();

    let creds_out = cognito_client
        .get_credentials_for_identity()
        .identity_id(identity_id)
        .send()
        .await
        .context("CognitoIdentity GetCredentialsForIdentity failed")?;
    let creds = creds_out
        .credentials()
        .ok_or_else(|| anyhow!("No credentials returned by Cognito Identity"))?;

    let session_token_opt = creds.session_token().map(|s| s.to_string());
    let creds = Credentials::new(
        creds.access_key_id().unwrap_or_default(),
        creds.secret_key().unwrap_or_default(),
        session_token_opt,
        None,
        "cognito-identity",
    );

    // 2) Use IoT API CreateKeysAndCertificate with temporary creds
    let shared = aws_config::defaults(BehaviorVersion::latest()).region(region).credentials_provider(creds).load().await;
    let iot_client = iot::Client::new(&shared);

    let out = iot_client
        .create_keys_and_certificate()
        .set_as_active(true)
        .send()
        .await
        .context("IoT CreateKeysAndCertificate failed (ensure IAM policy allows it)")?;

    iot_client.attach_policy().policy_name("pswpolicy").target(out.certificate_arn().unwrap_or_default()).send().await.context("IoT AttachPolicy failed")?;

    let cert_pem = out.certificate_pem().unwrap_or_default();
    let key_pair = out.key_pair().ok_or_else(|| anyhow!("No key pair returned"))?;
    let priv_pem = key_pair.private_key().unwrap_or_default();

    // 3) Save to config dir
    let cfg = config_home(cli)?;
    fs::create_dir_all(&cfg).context("creating config dir")?;
    fs::write(cfg.join("certificate.pem"), cert_pem).context("writing certificate.pem")?;
    fs::write(cfg.join("private.pem"), priv_pem).context("writing private.pem")?;

    // Ensure CA present for MQTT
    let _ = ensure_ca_pem(&cfg)?;

    println!("Saved certificate.pem and private.pem to {}", cfg.display());
    Ok(())
}

fn hex_id_from_decimal(decimal: &str) -> Result<String> {
    if !reclaim::validate_unique_id(decimal) {
        return Err(anyhow!("Invalid unique_id: must be 17 digits with valid checksum"));
    }
    let id_num: u64 = decimal.parse().context("parsing unique_id")?;
    //
    Ok(format!("{:012x}", id_num.shr(8)))
}

use rustls;
use rustls_pemfile::{Item, read_one};
use std::sync::Arc;

fn build_tls_config(cfg_dir: &Path) -> Result<Arc<rustls::ClientConfig>> {
    let ca_path = cfg_dir.join("AmazonRootCA1.pem");
    let cert_path = cfg_dir.join("certificate.pem");
    let key_path = cfg_dir.join("private.pem");

    let ca_pem = fs::read(&ca_path).with_context(|| format!("reading CA pem at {}", ca_path.display()))?;
    let cert_pem = fs::read(&cert_path).with_context(|| format!("reading certificate.pem at {}", cert_path.display()))?;
    let key_pem = fs::read(&key_path).with_context(|| format!("reading private.pem at {}", key_path.display()))?;

    // Root store from Amazon CA
    let mut root_store = rustls::RootCertStore::empty();
    let mut ca_reader = std::io::BufReader::new(&ca_pem[..]);
    let ca_der_list = rustls_pemfile::certs(&mut ca_reader)
        .map_err(|e| anyhow!("parsing CA pem: {e}"))?;
    root_store.add_parsable_certificates(&ca_der_list);

    // Client cert chain
    let mut certs_reader = std::io::BufReader::new(&cert_pem[..]);
    let cert_der_list = rustls_pemfile::certs(&mut certs_reader)
        .map_err(|e| anyhow!("parsing certificate.pem: {e}"))?;
    if cert_der_list.is_empty() {
        return Err(anyhow!("No X509 certificate found in certificate.pem"));
    }
    let certs: Vec<rustls::Certificate> = cert_der_list.into_iter().map(rustls::Certificate).collect();

    // Private key (supports PKCS#8, PKCS#1, SEC1)
    let mut key_reader = std::io::BufReader::new(&key_pem[..]);
    let mut private_key: Option<rustls::PrivateKey> = None;
    loop {
        match read_one(&mut key_reader)? {
            None => break,
            Some(Item::RSAKey(der)) => { private_key = Some(rustls::PrivateKey(der)); break; }
            Some(Item::PKCS8Key(der)) => { private_key = Some(rustls::PrivateKey(der)); break; }
            Some(Item::ECKey(der)) => { private_key = Some(rustls::PrivateKey(der)); break; }
            _ => {}
        }
    }
    let key = private_key.ok_or_else(|| anyhow!("No private key found in private.pem"))?;

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| anyhow!("building rustls ClientConfig: {e}"))?;

    Ok(Arc::new(config))
}

async fn subscribe(cli: &Cli, unique_id: &str) -> Result<()> {
    use mqtt::packet;
    use mqtt::packet::v3_1_1 as v3;
    use mqtt::{Endpoint, Mode, Version};
    use mqtt::transport::{TlsTransport, connect_helper};

    let cfg = config_home(cli)?;
    let _ = ensure_ca_pem(&cfg)?;

    // Informative warning if region and endpoint do not match
    if let Some(ep_region) = region_from_endpoint(&cli.endpoint) {
        if ep_region != cli.region {
            eprintln!(
                "Warning: endpoint region '{}' differs from configured region '{}'. Ensure certificates are created in the endpoint's region.",
                ep_region, cli.region
            );
        }
    }

    let hexid = hex_id_from_decimal(unique_id)?;
    let topic = format!("dontek{}/status/psw", hexid);
    let client_id = format!("reclaim-client-{}", hexid);

    // Lookup IP address
    let addr = format!("{}:{}", cli.endpoint, 8883);
    println!("Connecting to {}...", addr);
    let resolved = lookup_host(&addr).await?.next().ok_or_else(|| anyhow!("DNS lookup failed for {}", cli.endpoint))?;
    println!("Resolved to {}", resolved);

    // Build TLS config from pem files
    let tls_config = build_tls_config(&cfg)?;

    // Create endpoint and attach TLS transport
    let endpoint: Endpoint<mqtt::role::Client> = mqtt::Endpoint::new(Version::V3_1_1);

    let tls_stream = connect_helper::connect_tcp_tls(&resolved.to_string(), &cli.endpoint, Some(tls_config), None)
        .await
        .map_err(|e| anyhow!("TLS connect error: {e}"))?;
    let transport = TlsTransport::from_stream(tls_stream);

    endpoint.attach(transport, Mode::Client).await.map_err(|e| anyhow!("attach error: {e}"))?;

    // Send CONNECT
    let connect = v3::Connect::builder()
        .client_id(&client_id)
        .unwrap()
        .clean_session(true)
        .keep_alive(30)
        .build()
        .unwrap();
    endpoint.send(connect).await.map_err(|e| anyhow!("send CONNECT failed: {e}"))?;

    // Wait for CONNACK
    loop {
        let pkt = endpoint.recv().await.map_err(|e| anyhow!("recv error before CONNACK: {e}"))?;
        match pkt {
            packet::Packet::V3_1_1Connack(_ack) => {
                println!("Connected to {}", cli.endpoint);
                break;
            }
            _ => {
                // ignore other packets until connack
            }
        }
    }

    // Send SUBSCRIBE QoS 1
    let pid = endpoint.acquire_packet_id().await.map_err(|e| anyhow!("acquire pid failed: {e}"))?;
    let subscribe = v3::Subscribe::builder()
        .packet_id(pid)
        .entries({
            let opts = packet::SubOpts::new().set_qos(packet::Qos::AtLeastOnce);
            let entry = packet::SubEntry::new(&topic, opts).map_err(|e| anyhow!("bad topic filter: {e}"))?;
            vec![entry]
        })
        .build()
        .unwrap();
    endpoint.send(subscribe).await.map_err(|e| anyhow!("send SUBSCRIBE failed: {e}"))?;
    println!("Subscribed to {} on {}", topic, cli.endpoint);

    // Receive loop: print publish payloads
    loop {
        let pkt = endpoint.recv().await.map_err(|e| anyhow!("recv error: {e}"))?;
        match pkt {
            packet::Packet::V3_1_1Publish(p) => {
                let payload = String::from_utf8_lossy(p.payload().as_slice());
                println!("{}", payload);
            }
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::FetchCerts => fetch_and_save_certs(&cli).await,
        Commands::Subscribe { unique_id } => subscribe(&cli, unique_id).await, 
    }
}
