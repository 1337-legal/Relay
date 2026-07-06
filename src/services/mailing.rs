//! Mail forwarding: MX resolution, alias address (de)serialization, optional
//! PGP encryption, MIME assembly and DKIM-signed delivery.

use crate::config::Config;
use crate::services::address::{self, Deserialized};
use crate::services::encryption;
use crate::services::mime::{self, Attachment, MailContent, Threading};
use anyhow::Result;

/// Parameters for [`MailingService::send_mail`]. `in_reply_to` / `references`
/// are pre-joined to single strings at the call site.
#[derive(Debug, Clone, Default)]
pub struct SendMailParams {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub content: MailContent,
    pub public_key: Option<String>,
    pub attachments: Vec<Attachment>,
    pub reply_to: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
}

/// The addresses a send was accepted for.
#[derive(Debug, Clone, Default)]
pub struct SendOutcome {
    pub accepted: Vec<String>,
}

/// Forwards mail with DKIM signing and optional PGP encryption.
#[derive(Debug, Clone)]
pub struct MailingService {
    pub domain: String,
    pub selector: String,
    pub private_key: String,
}

impl MailingService {
    pub fn new(config: &Config) -> Self {
        Self {
            domain: config.dkim_domain.clone(),
            selector: config.dkim_selector.clone(),
            private_key: config.dkim_private_key.clone(),
        }
    }

    pub fn serialize_address(&self, from: &str, alias: &str) -> Option<String> {
        address::serialize_address(from, alias)
    }

    pub fn deserialize_address(&self, serialized: &str) -> Option<Deserialized> {
        address::deserialize_address(serialized)
    }

    /// Encrypt `content` to `public_key`, falling back to the plaintext on
    /// failure.
    pub fn encrypt_content(&self, content: &str, public_key: Option<&str>) -> String {
        let Some(key) = public_key else {
            return content.to_string();
        };
        match encryption::encrypt_email_content(content, key) {
            Ok(encrypted) => encrypted,
            Err(err) => {
                crate::logs::error(format!(
                    "Failed to encrypt content, sending unencrypted: {err}"
                ));
                content.to_string()
            }
        }
    }

    /// Resolve the highest-priority MX host for an address, returning
    /// `(host, 25)`.
    pub async fn resolve_mail_exchange(&self, email: &str) -> Result<(String, u16)> {
        transport::resolve_mail_exchange(email).await
    }

    /// Send mail, PGP-encrypting the body when a `public_key` is supplied.
    pub async fn send_mail(&self, params: SendMailParams) -> Result<SendOutcome> {
        let (host, port) = self.resolve_mail_exchange(&params.to).await?;

        let threading = Threading {
            reply_to: params.reply_to.clone(),
            message_id: params.message_id.clone(),
            in_reply_to: params.in_reply_to.clone(),
            references: params.references.clone(),
        };

        let raw_message = if let Some(public_key) = params.public_key.as_deref() {
            // PGP/MIME path: build inner MIME, encrypt it, wrap in
            // multipart/encrypted.
            let multipart = mime::create_multipart_content(&params.content, &params.attachments);
            let encrypted = self.encrypt_content(&multipart, Some(public_key));
            mime::create_pgp_mime_message(
                &params.from,
                &params.to,
                &params.subject,
                &encrypted,
                &threading,
            )
        } else {
            // Plain path: a normal multipart message with the same headers.
            transport::build_plain_message(&params, &threading)
        };

        transport::deliver(
            &host,
            port,
            &params.from,
            &params.to,
            raw_message.as_bytes(),
            &self.domain,
            &self.selector,
            &self.private_key,
        )
        .await
    }
}

// MX resolution + DKIM-signed SMTP delivery.
mod transport {
    use super::{SendMailParams, SendOutcome};
    use crate::services::dkim;
    use crate::services::mime::{self, Threading};
    use anyhow::{anyhow, Context, Result};
    use samotop_delivery::prelude::{EmailAddress, Envelope, SmtpClient, Transport};
    use samotop_delivery::smtp::ClientSecurity;
    use samotop_delivery::MailDataStream;

    /// Build a plain (unencrypted) raw MIME message with threading headers.
    pub fn build_plain_message(params: &SendMailParams, threading: &Threading) -> String {
        // Reuse the multipart/alternative (+mixed) builder for the body, then
        // prepend top-level headers.
        let body = mime::create_multipart_content(&params.content, &params.attachments);
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S +0000")
            .to_string();

        let mut msg = String::new();
        msg.push_str(&format!("From: {}\r\n", params.from));
        msg.push_str(&format!("To: {}\r\n", params.to));
        msg.push_str(&format!("Subject: {}\r\n", params.subject));
        msg.push_str(&format!("Date: {date}\r\n"));
        if let Some(v) = &threading.reply_to {
            msg.push_str(&format!("Reply-To: {v}\r\n"));
        }
        if let Some(v) = &threading.message_id {
            msg.push_str(&format!("Message-ID: {v}\r\n"));
        }
        if let Some(v) = &threading.in_reply_to {
            msg.push_str(&format!("In-Reply-To: {v}\r\n"));
        }
        if let Some(v) = &threading.references {
            msg.push_str(&format!("References: {v}\r\n"));
        }
        // `body` already begins with MIME-Version + Content-Type.
        msg.push_str(&body);
        msg
    }

    /// Extract the bare `addr` from a possibly display-name-wrapped address
    /// (`Name <addr>` → `addr`).
    fn extract_email(addr: &str) -> String {
        if let (Some(start), Some(end)) = (addr.find('<'), addr.find('>')) {
            if start < end {
                return addr[start + 1..end].to_string();
            }
        }
        addr.trim().to_string()
    }

    /// Resolve the highest-priority MX host for the recipient's domain,
    /// returning `(host, 25)`.
    pub async fn resolve_mail_exchange(email: &str) -> Result<(String, u16)> {
        let domain = email
            .split('@')
            .nth(1)
            .filter(|d| !d.is_empty())
            .ok_or_else(|| anyhow!("Invalid email address: {email}"))?;

        let resolver = async_std_resolver::resolver_from_system_conf()
            .await
            .with_context(|| format!("Failed to resolve MX for {domain}"))?;

        let lookup = resolver
            .mx_lookup(domain)
            .await
            .with_context(|| format!("Failed to resolve MX for {domain}"))?;

        // Lowest preference number = highest priority.
        let mut records: Vec<_> = lookup.iter().collect();
        records.sort_by_key(|r| r.preference());

        let first = records
            .first()
            .ok_or_else(|| anyhow!("No MX records found for domain: {domain}"))?;

        let exchange = first.exchange().to_utf8();
        let exchange = exchange.trim_end_matches('.').to_string();
        if exchange.is_empty() {
            return Err(anyhow!("Invalid MX record for domain: {domain}"));
        }
        Ok((exchange, 25))
    }

    /// DKIM-sign the raw message and deliver it to `host:port` over an
    /// opportunistic-STARTTLS SMTP session.
    #[allow(clippy::too_many_arguments)]
    pub async fn deliver(
        host: &str,
        port: u16,
        from: &str,
        to: &str,
        raw_message: &[u8],
        dkim_domain: &str,
        dkim_selector: &str,
        dkim_private_key: &str,
    ) -> Result<SendOutcome> {
        // Prepend a DKIM-Signature header.
        let dkim_header = dkim::sign_header(raw_message, dkim_domain, dkim_selector, dkim_private_key)?;
        let mut signed = Vec::with_capacity(dkim_header.len() + raw_message.len());
        signed.extend_from_slice(dkim_header.as_bytes());
        signed.extend_from_slice(raw_message);

        let envelope = Envelope::new(
            Some(EmailAddress::new(extract_email(from)).map_err(|e| anyhow!("bad from: {e}"))?),
            vec![EmailAddress::new(extract_email(to)).map_err(|e| anyhow!("bad to: {e}"))?],
            envelope_id(dkim_domain),
        )
        .map_err(|e| anyhow!("invalid envelope: {e}"))?;

        let address = format!("{host}:{port}");
        // Opportunistic STARTTLS: MX host certs are not pinned.
        let transport = SmtpClient::with_security(address, ClientSecurity::Opportunistic)
            .map_err(|e| anyhow!("smtp client setup failed: {e}"))?
            .connect();

        let stream = transport
            .send(envelope, futures::io::Cursor::new(signed))
            .await
            .map_err(|e| anyhow!("smtp send to {host} failed: {e}"))?;

        if stream.is_done() {
            Ok(SendOutcome {
                accepted: vec![to.to_string()],
            })
        } else {
            Err(anyhow!("smtp delivery to {host} did not complete"))
        }
    }

    /// A unique envelope/transaction id (`<millis.seq@domain>`-ish).
    fn envelope_id(domain: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        format!("{}.{seq}@{domain}", chrono::Utc::now().timestamp_millis())
    }
}
