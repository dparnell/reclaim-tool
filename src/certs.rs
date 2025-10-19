use anyhow::{anyhow, Context, Result};
use tracing::{info, warn};

use crate::cli::Cli;
use crate::util::{config_home, region_from_endpoint};

pub async fn fetch_and_save_certs(cli: &Cli) -> Result<()> {
    use aws_config::BehaviorVersion;
    use aws_config::Region;
    use aws_credential_types::Credentials;
    use aws_sdk_cognitoidentity as cognito;
    use aws_sdk_iot as iot;

    // Derive region from endpoint to avoid creating certs in the wrong region
    let ep_region = region_from_endpoint(&cli.endpoint);
    let chosen_region = ep_region.as_deref().unwrap_or(&cli.region);
    if let Some(ep) = &ep_region {
        if ep != &cli.region {
            warn!("endpoint region '{}' differs from configured region '{}'; using endpoint region", ep, cli.region);
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
    let cfg = config_home(&cli.config_dir)?;
    std::fs::create_dir_all(&cfg).context("creating config dir")?;
    std::fs::write(cfg.join("certificate.pem"), cert_pem).context("writing certificate.pem")?;
    std::fs::write(cfg.join("private.pem"), priv_pem).context("writing private.pem")?;

    // Ensure CA present for MQTT
    let _ = crate::tls::ensure_ca_pem(&cfg)?;

    info!("Saved certificate.pem and private.pem to {}", cfg.display());
    Ok(())
}
