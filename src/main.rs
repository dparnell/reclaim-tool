mod reclaim;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use dirs::config_dir;
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, Transport, TlsConfiguration};
use std::fs;
use std::io::Write;
use std::ops::Shr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use aws_config::BehaviorVersion;

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

    let region = Region::new(cli.region.clone());

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

    let creds = Credentials::new(
        creds.access_key_id().unwrap_or_default(),
        creds.secret_key().unwrap_or_default(),
        Some(creds.session_token().unwrap_or_default().to_string()),
        None,
        "cognito-identity",
    );

    // 2) Use IoT API CreateKeysAndCertificate with temporary creds
    let shared = aws_config::defaults(BehaviorVersion::latest()).region(region).credentials_provider(creds).load().await;
    let iot_client = iot::Client::new(&shared);

    let out = iot_client
        .create_keys_and_certificate()
        .set_set_as_active(Some(true))
        .send()
        .await
        .context("IoT CreateKeysAndCertificate failed (ensure IAM policy allows it)")?;

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

fn build_mqtt_options(endpoint: &str, client_id: &str, cfg_dir: &Path) -> Result<MqttOptions> {
    let mut options = MqttOptions::new(client_id, endpoint, 8883);
    options.set_keep_alive(Duration::from_secs(30));

    let ca_path = cfg_dir.join("AmazonRootCA1.pem");
    let cert_path = cfg_dir.join("certificate.pem");
    let key_path = cfg_dir.join("private.pem");

    let ca = fs::read(&ca_path).with_context(|| format!("reading CA pem at {}", ca_path.display()))?;
    let cert = fs::read(&cert_path).with_context(|| format!("reading certificate.pem at {}", cert_path.display()))?;
    let key = fs::read(&key_path).with_context(|| format!("reading private.pem at {}", key_path.display()))?;

    let tls_config = TlsConfiguration::Simple {
        ca,
        alpn: None,
        client_auth: Some((cert, key)),
    };
    options.set_transport(Transport::Tls(tls_config));

    Ok(options)
}

async fn subscribe(cli: &Cli, unique_id: &str) -> Result<()> {
    let cfg = config_home(cli)?;
    let _ = ensure_ca_pem(&cfg)?;

    let hexid = hex_id_from_decimal(unique_id)?;
    let topic = format!("dontek{}/status/psw", hexid);

    // Use hexid as client-id to keep it simple
    let mqttoptions = build_mqtt_options(&cli.endpoint, &format!("reclaim-client-{}", hexid), &cfg)?;

    println!("Connecting to {}", cli.endpoint);
    let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

    loop {
        match eventloop.poll().await {
            Ok(Event::Incoming(Packet::ConnAck(_))) => {
                println!("Connected to {}", cli.endpoint);
                client.subscribe(topic.clone(), QoS::AtLeastOnce).await?;
                println!("Subscribed to {} on {}", topic, cli.endpoint);
            }
            Ok(Event::Incoming(Packet::Publish(p))) => {
                let payload = String::from_utf8_lossy(&p.payload);
                println!("{}", payload);
            }
            Ok(v) => {println!("{:?}", v);}
            Err(e) => {
                return Err(anyhow!("MQTT error: {}", e));
            }
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
