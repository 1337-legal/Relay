//! DKIM signing.

use anyhow::{Context, Result};
use mail_auth::common::crypto::{RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::DkimSigner;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

/// Compute a `DKIM-Signature` header (including trailing CRLF) for the raw
/// message. The RSA key is accepted in either PKCS#1 or PKCS#8 PEM form and any
/// size (1024-bit DKIM keys included).
pub fn sign_header(
    raw_message: &[u8],
    domain: &str,
    selector: &str,
    private_key_pem: &str,
) -> Result<String> {
    // Parse either PEM layout, then normalize to PKCS#1 DER for mail-auth.
    let rsa_key = RsaPrivateKey::from_pkcs1_pem(private_key_pem)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(private_key_pem))
        .context("invalid DKIM RSA private key")?;
    let pkcs1_der = rsa_key
        .to_pkcs1_der()
        .context("failed to encode DKIM key")?;
    let key = RsaKey::<Sha256>::from_pkcs1_der(pkcs1_der.as_bytes())
        .context("failed to load DKIM key")?;

    let signature = DkimSigner::from_key(key)
        .domain(domain)
        .selector(selector)
        .headers(["From", "To", "Subject", "Date", "Message-ID"])
        .sign(raw_message)
        .context("DKIM signing failed")?;

    Ok(signature.to_header())
}
