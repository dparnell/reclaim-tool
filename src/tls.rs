use anyhow::{anyhow, Context, Result};
use rustls;
use rustls_pemfile::{Item, read_one};
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub fn ensure_ca_pem(path: &Path) -> Result<std::path::PathBuf> {
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
    use std::io::Write;
    f.write_all(pem.as_bytes()).context("writing CA pem")?;
    Ok(ca_path)
}

pub fn build_tls_config(cfg_dir: &Path) -> Result<Arc<rustls::ClientConfig>> {
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
