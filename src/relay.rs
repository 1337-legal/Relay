//! Core relay logic.
//!
//! Given the SMTP envelope recipient and the raw message bytes, decides whether
//! the mail is an inbound message to an alias or a reply from a user, performs
//! the database lookups, and forwards via [`MailingService`]. Kept independent
//! of the SMTP server plumbing so it can be unit-tested and the handler stays
//! thin.

use crate::logs;
use crate::repositories::alias;
use crate::services::mailing::{MailingService, SendMailParams, SendOutcome};
use crate::services::mime::{Attachment, MailContent};
use anyhow::{anyhow, Result};
use mail_parser::{Message, MessageParser, MimeHeaders};
use sqlx::PgPool;
use std::time::Instant;

/// Context shared across relayed messages: the DB pool and mailing service.
#[derive(Debug)]
pub struct Relay {
    pub pool: PgPool,
    pub mailing: MailingService,
}

impl Relay {
    pub fn new(pool: PgPool, mailing: MailingService) -> Self {
        Self { pool, mailing }
    }

    /// Process one message. `recipient` is the envelope RCPT TO address; `raw`
    /// is the full DATA payload. Returns `Ok(())` on successful forward, or an
    /// `Err` whose message is the rejection reason.
    pub async fn process(&self, recipient: &str, raw: &[u8]) -> Result<()> {
        let start = Instant::now();

        let mail = MessageParser::default()
            .parse(raw)
            .ok_or_else(|| anyhow!("Failed to parse email"))?;

        let sender = from_text(&mail).ok_or_else(|| anyhow!("No valid sender address found in email"))?;

        let is_reply = recipient.contains("_at_");
        if is_reply {
            self.handle_reply(&mail, &sender, recipient, start).await
        } else {
            self.handle_inbound(&mail, &sender, recipient, start).await
        }
    }

    /// A user replying via a serialized relay address, forwarded back to the
    /// original correspondent.
    async fn handle_reply(
        &self,
        mail: &Message<'_>,
        sender: &str,
        recipient: &str,
        start: Instant,
    ) -> Result<()> {
        let deserialized = self
            .mailing
            .deserialize_address(recipient)
            .ok_or_else(|| anyhow!("Failed to deserialize reply address"))?;

        let original_recipient = deserialized.from;
        let alias_address = deserialized.alias.to_lowercase();

        println!("Reply from {sender} via {alias_address} to {original_recipient}");

        // Resolve the alias's owner so we can verify the reply actually came
        // from them.
        let user = alias::get_user_by_alias(&self.pool, &alias_address)
            .await?
            .ok_or_else(|| anyhow!("No user found for alias: {alias_address}"))?;

        // Only the alias owner's real (hidden) address may relay a reply
        // through the alias. Without this check anyone who learns an alias
        // address — e.g. a past correspondent — could send spoofed,
        // DKIM-signed mail "from" that alias to an arbitrary destination by
        // crafting the right RCPT TO, since the SMTP server itself accepts
        // mail from any unauthenticated sender.
        let from_address = sender_address(mail)
            .ok_or_else(|| anyhow!("No sender address found in reply"))?;
        if !from_address.eq_ignore_ascii_case(&user.address) {
            logs::warning(format!(
                "Rejected reply via {alias_address}: sender {from_address} is not the alias owner"
            ));
            return Err(anyhow!(
                "Sender is not authorized to reply via alias: {alias_address}"
            ));
        }

        let alias_record = alias::get_alias_by_address(&self.pool, &alias_address).await?;
        match alias_record {
            Some(a) if a.status == "active" => {}
            _ => return Err(anyhow!("Alias not active: {alias_address}")),
        }

        // References chain: existing References + In-Reply-To if absent.
        let mut references_chain = references_list(mail);
        if let Some(in_reply_to) = in_reply_to_first(mail) {
            if !references_chain.iter().any(|r| r == &in_reply_to) {
                references_chain.push(in_reply_to);
            }
        }

        let outcome = self
            .mailing
            .send_mail(SendMailParams {
                from: alias_address.clone(),
                to: original_recipient.clone(),
                subject: subject_or_default(mail),
                content: content(mail),
                reply_to: Some(alias_address.clone()),
                in_reply_to: in_reply_to_first(mail),
                references: join_refs(&references_chain),
                attachments: attachments(mail),
                ..Default::default()
            })
            .await?;

        self.check_accepted(&outcome, &original_recipient)?;

        logs::success(format!(
            "[{}ms] [REDACTED] -> relay {alias_address} -> {original_recipient}",
            start.elapsed().as_millis()
        ));
        Ok(())
    }

    /// A fresh inbound message to an alias, forwarded (optionally encrypted) to
    /// the owning user's real address.
    async fn handle_inbound(
        &self,
        mail: &Message<'_>,
        sender: &str,
        recipient: &str,
        start: Instant,
    ) -> Result<()> {
        println!("Incoming email from {sender} to {recipient}");

        let user = alias::get_user_by_alias(&self.pool, recipient)
            .await?
            .ok_or_else(|| anyhow!("No user found for recipient alias: {recipient}"))?;

        let alias_record = alias::get_alias_by_address(&self.pool, recipient).await?;
        match alias_record {
            Some(a) if a.status == "active" => {}
            _ => return Err(anyhow!("No alias found for recipient address: {recipient}")),
        }

        let serialized_address = self
            .mailing
            .serialize_address(sender, recipient)
            .ok_or_else(|| anyhow!("Failed to serialize address for forwarding"))?;

        // References chain: existing References + this message's Message-ID.
        let mut references_chain = references_list(mail);
        if let Some(message_id) = mail.message_id() {
            let message_id = message_id.to_string();
            if !references_chain.iter().any(|r| r == &message_id) {
                references_chain.push(message_id);
            }
        }

        let outcome = self
            .mailing
            .send_mail(SendMailParams {
                from: serialized_address.clone(),
                to: user.address.clone(),
                subject: subject_or_default(mail),
                content: content(mail),
                public_key: user.pgp_public_key.clone(),
                in_reply_to: mail.message_id().map(|s| s.to_string()),
                references: join_refs(&references_chain),
                attachments: attachments(mail),
                ..Default::default()
            })
            .await?;

        self.check_accepted(&outcome, &user.address)?;

        logs::success(format!(
            "[{}ms] {sender} -> relay {serialized_address} -> [REDACTED]",
            start.elapsed().as_millis()
        ));
        Ok(())
    }

    fn check_accepted(&self, outcome: &SendOutcome, to: &str) -> Result<()> {
        if outcome.accepted.is_empty() {
            return Err(anyhow!("Failed to send email to: {to}"));
        }
        Ok(())
    }
}

/// The bare `From` address, ignoring any display name.
fn sender_address(mail: &Message<'_>) -> Option<String> {
    mail.from()?.first()?.address().map(|s| s.to_string())
}

/// Reconstruct the raw From text (`Name <addr>` or bare `addr`).
fn from_text(mail: &Message<'_>) -> Option<String> {
    let addr = mail.from()?.first()?;
    let address = addr.address()?;
    Some(match addr.name() {
        Some(name) if !name.is_empty() => format!("{name} <{address}>"),
        _ => address.to_string(),
    })
}

fn subject_or_default(mail: &Message<'_>) -> String {
    mail.subject().unwrap_or("No Subject").to_string()
}

/// Extract text + html bodies.
fn content(mail: &Message<'_>) -> MailContent {
    MailContent {
        text: mail.body_text(0).map(|c| c.into_owned()),
        html: mail.body_html(0).map(|c| c.into_owned()),
    }
}

/// The `References` header as a list of message-ids.
fn references_list(mail: &Message<'_>) -> Vec<String> {
    mail.references()
        .as_text_list()
        .map(|list| list.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

/// The first `In-Reply-To` message-id, if any.
fn in_reply_to_first(mail: &Message<'_>) -> Option<String> {
    mail.in_reply_to()
        .as_text_list()
        .and_then(|list| list.first().map(|s| s.to_string()))
        .or_else(|| mail.in_reply_to().as_text().map(|s| s.to_string()))
}

/// Join a references chain into a single space-separated header value.
fn join_refs(chain: &[String]) -> Option<String> {
    if chain.is_empty() {
        None
    } else {
        Some(chain.join(" "))
    }
}

/// Map parsed attachments onto our [`Attachment`] shape.
fn attachments(mail: &Message<'_>) -> Vec<Attachment> {
    mail.attachments()
        .map(|part| Attachment {
            filename: part.attachment_name().map(|s| s.to_string()),
            content_type: part.content_type().map(|ct| match ct.c_subtype.as_ref() {
                Some(sub) => format!("{}/{}", ct.c_type, sub),
                None => ct.c_type.to_string(),
            }),
            content_disposition: part.content_disposition().map(|cd| cd.c_type.to_string()),
            content: part.contents().to_vec(),
            cid: part.content_id().map(|s| s.to_string()),
        })
        .collect()
}
