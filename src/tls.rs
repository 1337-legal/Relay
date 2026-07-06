//! Server-side TLS configuration for STARTTLS.
//!
//! Builds a `rustls::ServerConfig` from the PEM certificate chain and private
//! key. `RELAY_CERTIFICATES` / `RELAY_PRIVATE_KEY` hold the PEM *contents*
//! directly, not file paths.
//!
//! Note: async-tls 0.11 links rustls 0.19, so this uses that version's API
//! (`internal::pemfile`, `NoClientAuth`, `set_single_cert`).

use anyhow::{anyhow, Context, Result};
use rustls::internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use rustls::{NoClientAuth, PrivateKey, ServerConfig};
use std::io::BufReader;

/// Build a `ServerConfig` from the PEM certificate chain and private key
/// contents. The key may be PKCS#8 or PKCS#1 (RSA) PEM.
pub fn load_server_config(cert_pem: &str, key_pem: &str) -> Result<ServerConfig> {
    // Tolerate keys/certs stored with literal `\n` escapes; a no-op when real
    // newlines are already present.
    let cert_pem = cert_pem.replace("\\n", "\n");
    let key_pem = key_pem.replace("\\n", "\n");

    let certs = certs(&mut BufReader::new(cert_pem.as_bytes()))
        .map_err(|_| anyhow!("Could not parse certificates from RELAY_CERTIFICATES"))?;
    if certs.is_empty() {
        return Err(anyhow!("No certificates found in RELAY_CERTIFICATES"));
    }

    let key = load_private_key(&key_pem)?;

    let mut config = ServerConfig::new(NoClientAuth::new());
    config
        .set_single_cert(certs, key)
        .context("failed to apply cert/key to TLS config")?;
    Ok(config)
}

/// Read the first private key from PEM contents, trying PKCS#8 then PKCS#1.
fn load_private_key(key_pem: &str) -> Result<PrivateKey> {
    if let Ok(mut keys) = pkcs8_private_keys(&mut BufReader::new(key_pem.as_bytes())) {
        if let Some(key) = keys.drain(..).next() {
            return Ok(key);
        }
    }
    if let Ok(mut keys) = rsa_private_keys(&mut BufReader::new(key_pem.as_bytes())) {
        if let Some(key) = keys.drain(..).next() {
            return Ok(key);
        }
    }
    Err(anyhow!(
        "No usable private key found in RELAY_PRIVATE_KEY (expected PKCS#8 or PKCS#1 PEM)"
    ))
}
