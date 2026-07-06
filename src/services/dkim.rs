//! DKIM signing.

use anyhow::{Context, Result};
use mail_auth::common::crypto::{RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::DkimSigner;

/// Compute a `DKIM-Signature` header (including trailing CRLF) for the raw
/// message. The RSA key is accepted in either PKCS#1 or PKCS#8 PEM form.
pub fn sign_header(
    raw_message: &[u8],
    domain: &str,
    selector: &str,
    private_key_pem: &str,
) -> Result<String> {
    let key = RsaKey::<Sha256>::from_rsa_pem(private_key_pem)
        .or_else(|_| RsaKey::<Sha256>::from_pkcs8_pem(private_key_pem))
        .context("invalid DKIM RSA private key")?;

    let signature = DkimSigner::from_key(key)
        .domain(domain)
        .selector(selector)
        .headers(["From", "To", "Subject", "Date", "Message-ID"])
        .sign(raw_message)
        .context("DKIM signing failed")?;

    Ok(signature.to_header())
}
