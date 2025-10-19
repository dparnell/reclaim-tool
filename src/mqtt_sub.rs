use anyhow::{anyhow, Result};
use mqtt_endpoint_tokio::mqtt_ep as mqtt;
use tokio::net::lookup_host;
use tracing::{info, warn};

use crate::cli::Cli;
use crate::tls::build_tls_config;
use crate::util::{config_home, hex_id_from_decimal, region_from_endpoint};

pub async fn subscribe(cli: &Cli, unique_id: &str) -> Result<()> {
    use mqtt::packet;
    use mqtt::packet::v3_1_1 as v3;
    use mqtt::{Endpoint, Mode, Version};
    use mqtt::transport::{TlsTransport, connect_helper};

    let cfg = config_home(&cli.config_dir)?;
    let _ = crate::tls::ensure_ca_pem(&cfg)?;

    // Informative warning if region and endpoint do not match
    if let Some(ep_region) = region_from_endpoint(&cli.endpoint) {
        if ep_region != cli.region {
            warn!(
                "endpoint region '{}' differs from configured region '{}'. Ensure certificates are created in the endpoint's region.",
                ep_region, cli.region
            );
        }
    }

    let hexid = hex_id_from_decimal(unique_id)?;
    let topic = format!("dontek{}/status/psw", hexid);
    let client_id = format!("reclaim-client-{}", hexid);

    // Lookup IP address
    let addr = format!("{}:{}", cli.endpoint, 8883);
    info!("Connecting to {}...", addr);
    let resolved = lookup_host(&addr).await?.next().ok_or_else(|| anyhow!("DNS lookup failed for {}", cli.endpoint))?;
    info!("Resolved to {}", resolved);

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
                info!("Connected to {}", cli.endpoint);
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
    info!("Subscribed to {} on {}", topic, cli.endpoint);

    // Receive loop: print publish payloads
    loop {
        let pkt = endpoint.recv().await.map_err(|e| anyhow!("recv error: {e}"))?;
        match pkt {
            packet::Packet::V3_1_1Publish(p) => {
                let payload = String::from_utf8_lossy(p.payload().as_slice());
                info!("{}", payload);
            }
            _ => {}
        }
    }
}
