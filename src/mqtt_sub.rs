use std::str::FromStr;
use anyhow::{anyhow, Result};
use mqtt_endpoint_tokio::mqtt_ep as mqtt;
use tokio::net::lookup_host;
use tokio::time::{interval, Duration};
use tracing::{info, warn, error};

use crate::cli::Cli;
use crate::tls::build_tls_config;
use crate::util::{config_home, hex_id_from_decimal, region_from_endpoint};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

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
    let cmd_topic = format!("dontek{}/cmd/psw", hexid);
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
        .keep_alive(60)
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

    // JSON payload for refresh requests
    let refresh_payload = "{\"messageId\": \"read\", \"modbusReg\": 1, \"modbusVal\": [1]}";

    // Send an immediate refresh request after establishing connection and subscribing
    {
        let pid = endpoint.acquire_packet_id().await.map_err(|e| anyhow!("acquire pid failed: {e}"))?;
        let publish = v3::Publish::builder()
            .topic_name(&cmd_topic)
            .unwrap()
            .qos(packet::Qos::AtLeastOnce)
            .packet_id(pid)
            .payload(refresh_payload)
            .build()
            .unwrap();
        endpoint.send(publish).await.map_err(|e| anyhow!("send PUBLISH failed: {e}"))?;
        info!("Sent initial refresh request to {}", cmd_topic);
    }

    // Setup periodic refresh publisher (first tick after the interval)
    let mut ticker = interval(Duration::from_secs(cli.refresh_interval));
    // Consume the immediate first tick so subsequent ticks occur after the full interval
    ticker.tick().await;

    // Combined loop: receive publishes and send periodic command
    loop {
        tokio::select! {
            pkt = endpoint.recv() => {
                let pkt = pkt.map_err(|e| anyhow!("recv error: {e}"))?;
                match pkt {
                    packet::Packet::V3_1_1Publish(p) => {
                        let payload = String::from_utf8_lossy(p.payload().as_slice());

                        match crate::reclaim::ReclaimState::from_str(&payload) {
                            Ok(state) => {
                                info!("{:#?}", state);
                                // Optionally write raw payload to file
                                if let Some(path) = &cli.out_file {
                                    if let Err(e) = append_line(path, &payload).await { error!("Failed to write to file {:?}: {}", path, e); }
                                }
                                // Optionally write to InfluxDB
                                if let Some(url) = &cli.influx_url {
                                    if let (Some(org), Some(bucket)) = (&cli.influx_org, &cli.influx_bucket) {
                                        if let Err(e) = write_influx(url, org, bucket, cli.influx_token.as_deref(), &cli.influx_measurement, unique_id, &cli.region, &state).await {
                                            warn!("Influx write failed: {}", e);
                                        }
                                    } else {
                                        warn!("influx_url provided but influx_org/influx_bucket not set; skipping write");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse ReclaimState: {}", e);
                                // Still write raw payload to file if configured
                                if let Some(path) = &cli.out_file {
                                    if let Err(e) = append_line(path, &payload).await { error!("Failed to write to file {:?}: {}", path, e); }
                                }
                            }
                        }
                    }
                    // Ignore other packets (including PUBACK for our QoS1 publishes)
                    _ => {}
                }
            }
            _ = ticker.tick() => {
                // Send periodic read command to cmd topic
                let pid = endpoint.acquire_packet_id().await.map_err(|e| anyhow!("acquire pid failed: {e}"))?;
                let publish = v3::Publish::builder()
                    .topic_name(&cmd_topic)
                    .unwrap()
                    .qos(packet::Qos::AtLeastOnce)
                    .packet_id(pid)
                    .payload(refresh_payload)
                    .build()
                    .unwrap();
                endpoint.send(publish).await.map_err(|e| anyhow!("send PUBLISH failed: {e}"))?;
                info!("Sent refresh request to {}", cmd_topic);
            }
        }
    }
}

async fn append_line(path: &std::path::PathBuf, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() { tokio::fs::create_dir_all(parent).await.ok(); }
    let mut f = OpenOptions::new().append(true).create(true).open(path).await?;
    f.write_all(line.as_bytes()).await?;
    f.write_all(b"\n").await?;
    Ok(())
}

fn to_line_protocol(measurement: &str, unique_id: &str, region: &str, state: &crate::reclaim::ReclaimState, timestamp_ns: i128) -> String {
    // tags
    let mut line = format!("{measurement},unique_id={unique_id},region={region}");
    // fields (booleans as integers)
    let fields = vec![
        ("pump_active", if state.pump_active { "1i".to_string() } else { "0i".to_string() }),
        ("case_temperature", format!("{}", state.case_temperature)),
        ("water_temperature", format!("{}", state.water_temperature)),
        ("outlet_temperature", format!("{}", state.outlet_temperature)),
        ("inlet_temperature", format!("{}", state.inlet_temperature)),
        ("discharge_temperature", format!("{}", state.discharge_temperature)),
        ("suction", format!("{}", state.suction)),
        ("evaporator", format!("{}", state.evaporator)),
        ("ambient_temperature", format!("{}", state.ambient_temperature)),
        ("compressor_speed", format!("{}", state.compressor_speed)),
        ("water_speed", format!("{}", state.water_speed)),
        ("fan_speed", format!("{}", state.fan_speed)),
        ("power", format!("{}", state.power)),
        ("current", format!("{}", state.current)),
    ];
    line.push(' ');
    line.push_str(&fields.into_iter().map(|(k,v)| format!("{k}={v}")).collect::<Vec<_>>().join(","));
    line.push(' ');
    line.push_str(&timestamp_ns.to_string());
    line
}

async fn write_influx(
    base_url: &str,
    org: &str,
    bucket: &str,
    token: Option<&str>,
    measurement: &str,
    unique_id: &str,
    region: &str,
    state: &crate::reclaim::ReclaimState,
) -> Result<()> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    let ts_ns: i128 = (now.as_secs() as i128) * 1_000_000_000 + (now.subsec_nanos() as i128);
    let line = to_line_protocol(measurement, unique_id, region, state, ts_ns);

    let url = format!("{}/api/v2/write?org={}&bucket={}&precision=ns", base_url.trim_end_matches('/'), urlencoding::encode(org), urlencoding::encode(bucket));
    let client = reqwest::Client::new();
    let mut req = client.post(url).header("Content-Type", "text/plain; charset=utf-8").body(line);
    if let Some(tok) = token { req = req.header("Authorization", format!("Token {}", tok)); }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("InfluxDB write failed: {} {}", status, text));
    }
    Ok(())
}
