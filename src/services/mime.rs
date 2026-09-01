//! MIME message construction for PGP/MIME (RFC 3156) delivery.

use base64::Engine;
use chrono::Utc;
use std::sync::atomic::{AtomicU64, Ordering};

/// An email attachment.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub content_disposition: Option<String>,
    pub content: Vec<u8>,
    pub cid: Option<String>,
}

/// Email body content: optional plain text and/or HTML.
#[derive(Debug, Clone, Default)]
pub struct MailContent {
    pub text: Option<String>,
    pub html: Option<String>,
}

/// Monotonic counter that keeps MIME boundaries unique within a process.
static BOUNDARY_SEQ: AtomicU64 = AtomicU64::new(0);

/// Build a unique boundary token: `{prefix}{millis}_{seq}`.
fn boundary(prefix: &str) -> String {
    let seq = BOUNDARY_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}{}_{seq}", Utc::now().timestamp_millis())
}

/// Wrap base64 text at 76 columns.
fn chunk_base64(b64: &str) -> String {
    let mut out = String::with_capacity(b64.len() + b64.len() / 76 * 2);
    for (i, ch) in b64.chars().enumerate() {
        if i > 0 && i % 76 == 0 {
            out.push_str("\r\n");
        }
        out.push(ch);
    }
    out.trim().to_string()
}

/// Input bytes per RFC 2047 encoded-word: 75 characters minus the delimiters
/// leaves 60 base64 characters once rounded to a multiple of 4.
const MAX_ENCODED_CHUNK: usize = 45;

/// Encode a header value as RFC 2047 encoded-words unless it is already
/// printable US-ASCII. Keeps 8-bit bytes — and injected line breaks — out of
/// headers.
pub fn encode_header_text(value: &str) -> String {
    if value.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return value.to_string();
    }

    // Chunk on character boundaries so every word decodes to valid UTF-8.
    let mut words = Vec::new();
    let mut chunk = String::new();
    for ch in value.chars() {
        if chunk.len() + ch.len_utf8() > MAX_ENCODED_CHUNK {
            words.push(encode_word(&chunk));
            chunk.clear();
        }
        chunk.push(ch);
    }
    if !chunk.is_empty() {
        words.push(encode_word(&chunk));
    }
    words.join(" ")
}

fn encode_word(chunk: &str) -> String {
    format!(
        "=?UTF-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode(chunk)
    )
}

/// Escape `"` and `\` in a MIME header parameter value.
fn encode_header_param(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Build the inner MIME body that is encrypted for PGP/MIME delivery.
///
/// Produces `multipart/alternative` (text + html) when there are no
/// attachments, otherwise `multipart/mixed` wrapping the alternative part plus
/// base64-encoded attachments.
pub fn create_multipart_content(content: &MailContent, attachments: &[Attachment]) -> String {
    if attachments.is_empty() {
        let b = boundary("----=_Part_");
        let mut mime = String::new();
        mime.push_str("MIME-Version: 1.0\r\n");
        mime.push_str(&format!(
            "Content-Type: multipart/alternative; boundary=\"{b}\"\r\n\r\n"
        ));

        if let Some(text) = &content.text {
            mime.push_str(&format!("--{b}\r\n"));
            mime.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            mime.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
            mime.push_str(&format!("{text}\r\n\r\n"));
        }
        if let Some(html) = &content.html {
            mime.push_str(&format!("--{b}\r\n"));
            mime.push_str("Content-Type: text/html; charset=utf-8\r\n");
            mime.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
            mime.push_str(&format!("{html}\r\n\r\n"));
        }

        mime.push_str(&format!("--{b}--\r\n"));
        return mime;
    }

    let mixed = boundary("----=_Mixed_");
    let alt = boundary("----=_Alt_");

    let mut mime = String::new();
    mime.push_str("MIME-Version: 1.0\r\n");
    mime.push_str(&format!(
        "Content-Type: multipart/mixed; boundary=\"{mixed}\"\r\n\r\n"
    ));

    mime.push_str(&format!("--{mixed}\r\n"));
    mime.push_str(&format!(
        "Content-Type: multipart/alternative; boundary=\"{alt}\"\r\n\r\n"
    ));

    if let Some(text) = &content.text {
        mime.push_str(&format!("--{alt}\r\n"));
        mime.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        mime.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
        mime.push_str(&format!("{text}\r\n\r\n"));
    }
    if let Some(html) = &content.html {
        mime.push_str(&format!("--{alt}\r\n"));
        mime.push_str("Content-Type: text/html; charset=utf-8\r\n");
        mime.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
        mime.push_str(&format!("{html}\r\n\r\n"));
    }

    mime.push_str(&format!("--{alt}--\r\n\r\n"));

    for att in attachments {
        let filename = att.filename.as_deref().unwrap_or("attachment");
        let content_type = att
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");
        let disposition = match att.content_disposition.as_deref() {
            Some(d) if d.eq_ignore_ascii_case("inline") => "inline",
            _ => "attachment",
        };
        let b64 = chunk_base64(&base64::engine::general_purpose::STANDARD.encode(&att.content));

        mime.push_str(&format!("--{mixed}\r\n"));
        mime.push_str(&format!(
            "Content-Type: {content_type}; name=\"{}\"\r\n",
            encode_header_param(filename)
        ));
        mime.push_str("Content-Transfer-Encoding: base64\r\n");
        mime.push_str(&format!(
            "Content-Disposition: {disposition}; filename=\"{}\"\r\n",
            encode_header_param(filename)
        ));
        if let Some(cid) = &att.cid {
            mime.push_str(&format!("Content-ID: <{cid}>\r\n"));
        }
        mime.push_str(&format!("\r\n{b64}\r\n\r\n"));
    }

    mime.push_str(&format!("--{mixed}--\r\n"));
    mime
}

/// Threading and identity headers threaded through the outgoing message.
#[derive(Debug, Clone, Default)]
pub struct Threading {
    pub reply_to: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
}

/// Wrap `encrypted_content` in a `multipart/encrypted` (PGP/MIME) message with
/// full headers, ready to hand to the transport as a raw message.
pub fn create_pgp_mime_message(
    from: &str,
    to: &str,
    subject: &str,
    encrypted_content: &str,
    threading: &Threading,
) -> String {
    let b = boundary("----=_NextPart_");
    let date = Utc::now().format("%a, %d %b %Y %H:%M:%S +0000").to_string();

    let mut message = String::new();
    message.push_str(&format!("From: {from}\r\n"));
    message.push_str(&format!("To: {to}\r\n"));
    message.push_str(&format!("Subject: {}\r\n", encode_header_text(subject)));
    message.push_str(&format!("Date: {date}\r\n"));
    if let Some(reply_to) = &threading.reply_to {
        message.push_str(&format!("Reply-To: {reply_to}\r\n"));
    }
    if let Some(message_id) = &threading.message_id {
        message.push_str(&format!("Message-ID: {message_id}\r\n"));
    }
    if let Some(in_reply_to) = &threading.in_reply_to {
        message.push_str(&format!("In-Reply-To: {in_reply_to}\r\n"));
    }
    if let Some(references) = &threading.references {
        message.push_str(&format!("References: {references}\r\n"));
    }
    message.push_str("MIME-Version: 1.0\r\n");
    message.push_str(&format!(
        "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{b}\"\r\n\r\n"
    ));

    // First part: PGP version indicator.
    message.push_str(&format!("--{b}\r\n"));
    message.push_str("Content-Type: application/pgp-encrypted\r\n");
    message.push_str("Content-Description: PGP/MIME version identification\r\n\r\n");
    message.push_str("Version: 1\r\n\r\n");

    // Second part: encrypted payload.
    message.push_str(&format!("--{b}\r\n"));
    message.push_str("Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n");
    message.push_str("Content-Description: OpenPGP encrypted message\r\n");
    message.push_str("Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n");
    message.push_str(&format!("{encrypted_content}\r\n"));

    message.push_str(&format!("--{b}--\r\n"));
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_wraps_at_76() {
        let s = "a".repeat(200);
        let chunked = chunk_base64(&s);
        for line in chunked.split("\r\n") {
            assert!(line.len() <= 76);
        }
    }

    #[test]
    fn ascii_header_text_is_left_alone() {
        assert_eq!(
            encode_header_text("Your eBay order #42"),
            "Your eBay order #42"
        );
        assert_eq!(encode_header_text(""), "");
    }

    #[test]
    fn non_ascii_header_text_is_encoded() {
        assert_eq!(encode_header_text("Société"), "=?UTF-8?B?U29jacOpdMOp?=");
    }

    #[test]
    fn header_text_cannot_inject_a_header() {
        let encoded = encode_header_text("Hi\r\nBcc: victim@example.com");
        assert!(
            !encoded.contains('\r') && !encoded.contains('\n'),
            "{encoded}"
        );
    }

    #[test]
    fn long_non_ascii_header_text_splits_into_valid_words() {
        let encoded = encode_header_text(&"é".repeat(100));
        let mut decoded = Vec::new();
        for word in encoded.split(' ') {
            let payload = word
                .strip_prefix("=?UTF-8?B?")
                .and_then(|w| w.strip_suffix("?="))
                .unwrap_or_else(|| panic!("not an encoded word: {word}"));
            assert!(word.len() <= 75, "encoded word too long: {word}");
            decoded.extend(
                base64::engine::general_purpose::STANDARD
                    .decode(payload)
                    .unwrap(),
            );
        }
        assert_eq!(String::from_utf8(decoded).unwrap(), "é".repeat(100));
    }

    #[test]
    fn header_param_escaping() {
        assert_eq!(encode_header_param(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn alternative_without_attachments() {
        let content = MailContent {
            text: Some("hello".into()),
            html: Some("<b>hello</b>".into()),
        };
        let mime = create_multipart_content(&content, &[]);
        assert!(mime.contains("multipart/alternative"));
        assert!(mime.contains("text/plain"));
        assert!(mime.contains("text/html"));
        assert!(!mime.contains("multipart/mixed"));
    }

    #[test]
    fn mixed_with_attachment() {
        let content = MailContent {
            text: Some("hi".into()),
            html: None,
        };
        let att = Attachment {
            filename: Some("f.txt".into()),
            content_type: Some("text/plain".into()),
            content_disposition: None,
            content: b"data".to_vec(),
            cid: None,
        };
        let mime = create_multipart_content(&content, &[att]);
        assert!(mime.contains("multipart/mixed"));
        assert!(mime.contains("base64"));
    }
}
