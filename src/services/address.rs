//! Alias address parsing and (de)serialization.
//!
//! Encodes an original sender + alias into a single reply-able relay address and
//! back again, using the `_at_` and `_` separators.

use crate::services::mime::encode_header_text;

/// Stand-in for `@` inside a serialized relay local part.
const AT_MARKER: &str = "_at_";

/// RFC 5322 `specials`: a display name containing any of these must be quoted.
const SPECIALS: &str = "()<>[]:;@\\,.\"";

/// A parsed `Display <addr>` mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub name: Option<String>,
    pub address: String,
}

/// The original address paired with its alias, recovered from a relay address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deserialized {
    pub from: String,
    pub alias: String,
}

/// Everything after the last `@`, or `None` when there is no domain.
pub fn get_domain_from_email(email: &str) -> Option<String> {
    email.rsplit_once('@').map(|(_, domain)| domain.to_string())
}

/// Whether an address is a serialized relay-back address rather than a plain
/// alias, i.e. whether mail sent to it is a reply to forward onwards.
pub fn is_relay_address(address: &str) -> bool {
    address.contains(AT_MARKER)
}

/// Parse `Display <addr>`, `<addr>` or a bare `addr`, taking the address from
/// the last angle-bracket pair and dropping control characters.
pub fn parse_mailbox(input: &str) -> Option<Mailbox> {
    let cleaned = strip_controls(input);
    let input = cleaned.trim();

    let (name, address) = match input.rfind('<') {
        Some(start) => {
            let rest = &input[start + 1..];
            (input[..start].trim(), rest[..rest.find('>')?].trim())
        }
        None => ("", input),
    };

    // A mailbox is a single token with a non-empty local part and domain.
    if address.contains(char::is_whitespace) {
        return None;
    }
    let (local, domain) = address.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }

    let name = unquote(name);
    Some(Mailbox {
        name: (!name.is_empty()).then_some(name),
        address: address.to_string(),
    })
}

/// Render a mailbox as a header value, quoting or MIME-encoding the display
/// name as needed.
pub fn format_mailbox(name: Option<&str>, address: &str) -> String {
    match name.map(str::trim).filter(|name| !name.is_empty()) {
        None => address.to_string(),
        Some(name) => format!("{} <{address}>", encode_display_name(name)),
    }
}

/// Serialize an original sender + alias into a single relay-back address.
///
/// `("bob@example.com", "alice@1337.legal")` →
/// `"bob_at_example.com_alice@1337.legal"`. A display name is preserved:
/// `"Bob <bob@example.com>"` → `"Bob <bob_at_...@1337.legal>"`.
pub fn serialize_address(from: &str, alias: &str) -> Option<String> {
    let sender = parse_mailbox(from)?;
    let serialized = serialize_bare(&sender.address, alias)?;
    Some(format_mailbox(sender.name.as_deref(), &serialized))
}

/// [`serialize_address`] without the display name, i.e. the bare relay-back
/// address.
pub fn serialize_bare(from: &str, alias: &str) -> Option<String> {
    let from = parse_mailbox(from)?.address;
    let (from_local, from_domain) = from.rsplit_once('@')?;
    let alias = parse_mailbox(alias)?.address;
    let (alias_local, alias_domain) = alias.rsplit_once('@')?;

    Some(format!(
        "{from_local}{AT_MARKER}{from_domain}_{alias_local}@{alias_domain}"
    ))
}

/// Reverse [`serialize_address`], recovering the original sender and alias.
///
/// `"bob_at_example.com_alice@1337.legal"` →
/// `{ from: "bob@example.com", alias: "alice@1337.legal" }`.
pub fn deserialize_address(serialized: &str) -> Option<Deserialized> {
    let relay = parse_mailbox(serialized)?.address;
    let (local, domain) = relay.rsplit_once('@')?;

    // Split on the *last* marker: the original local part may contain `_at_`
    // of its own, as provider relay addresses do.
    let (original_local, tail) = local.rsplit_once(AT_MARKER)?;
    // Domains cannot contain `_`, so the tail's first underscore ends the
    // original domain; the alias local part after it may contain more.
    let (original_domain, alias_local) = tail.split_once('_')?;

    if original_local.is_empty() || alias_local.is_empty() || !original_domain.contains('.') {
        return None;
    }

    Some(Deserialized {
        from: format!("{original_local}@{original_domain}"),
        alias: format!("{alias_local}@{domain}"),
    })
}

/// Drop ASCII control characters, CR and LF included.
fn strip_controls(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

/// Strip the quotes of an RFC 5322 quoted-string display name and undo its
/// backslash escapes.
fn unquote(name: &str) -> String {
    let name = name.trim();
    let Some(inner) = name.strip_prefix('"').and_then(|n| n.strip_suffix('"')) else {
        return name.to_string();
    };

    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            _ => out.push(c),
        }
    }
    out
}

/// Quote — or MIME-encode — a display name so it is safe to place in a header.
fn encode_display_name(name: &str) -> String {
    // An encoded-word is a bare atom and must not be quoted.
    let encoded = encode_header_text(name);
    if encoded != name {
        return encoded;
    }
    if name.contains(|c| SPECIALS.contains(c)) {
        let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
        return format!("\"{escaped}\"");
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private-relay sender whose own local part contains `_at_`.
    const APPLE_RELAY: &str =
        "ebay_at_information_ebay_fr_vgzn7n2xx8_536b29e7@privaterelay.appleid.com";

    #[test]
    fn domain_extraction() {
        assert_eq!(get_domain_from_email("bob@example.com").as_deref(), Some("example.com"));
        assert_eq!(get_domain_from_email("no-at-sign"), None);
    }

    #[test]
    fn serialize_bare_address() {
        assert_eq!(
            serialize_address("bob@example.com", "alice@1337.legal").as_deref(),
            Some("bob_at_example.com_alice@1337.legal")
        );
    }

    #[test]
    fn serialize_with_display_name() {
        assert_eq!(
            serialize_address("Bob Smith <bob@example.com>", "alice@1337.legal").as_deref(),
            Some("Bob Smith <bob_at_example.com_alice@1337.legal>")
        );
    }

    #[test]
    fn deserialize_bare_address() {
        assert_eq!(
            deserialize_address("bob_at_example.com_alice@1337.legal"),
            Some(Deserialized {
                from: "bob@example.com".into(),
                alias: "alice@1337.legal".into(),
            })
        );
    }

    #[test]
    fn deserialize_with_display_name() {
        assert_eq!(
            deserialize_address("Bob Smith <bob_at_example.com_alice@1337.legal>"),
            Some(Deserialized {
                from: "bob@example.com".into(),
                alias: "alice@1337.legal".into(),
            })
        );
    }

    #[test]
    fn round_trip() {
        let serialized = serialize_address("bob@example.com", "alice@1337.legal").unwrap();
        let back = deserialize_address(&serialized).unwrap();
        assert_eq!(back.from, "bob@example.com");
        assert_eq!(back.alias, "alice@1337.legal");
    }

    #[test]
    fn round_trip_sender_whose_local_part_contains_the_marker() {
        let serialized = serialize_bare(APPLE_RELAY, "describe-above-crunch@1337.legal").unwrap();
        let back = deserialize_address(&serialized).unwrap();
        assert_eq!(back.from, APPLE_RELAY);
        assert_eq!(back.alias, "describe-above-crunch@1337.legal");
    }

    #[test]
    fn round_trip_alias_local_part_containing_underscores() {
        let serialized = serialize_bare("bob@example.com", "a_b_c@1337.legal").unwrap();
        let back = deserialize_address(&serialized).unwrap();
        assert_eq!(back.from, "bob@example.com");
        assert_eq!(back.alias, "a_b_c@1337.legal");
    }

    #[test]
    fn round_trip_sender_local_part_containing_underscores() {
        let serialized = serialize_bare("bob_smith@example.com", "alice@1337.legal").unwrap();
        let back = deserialize_address(&serialized).unwrap();
        assert_eq!(back.from, "bob_smith@example.com");
        assert_eq!(back.alias, "alice@1337.legal");
    }

    #[test]
    fn relay_address_detection() {
        assert!(is_relay_address("bob_at_example.com_alice@1337.legal"));
        assert!(!is_relay_address("describe-above-crunch@1337.legal"));
    }

    #[test]
    fn parse_display_name_containing_angle_bracket() {
        let mailbox = parse_mailbox("dev <ops <bob@example.com>").unwrap();
        assert_eq!(mailbox.address, "bob@example.com");
        assert_eq!(mailbox.name.as_deref(), Some("dev <ops"));
    }

    #[test]
    fn parse_quoted_display_name() {
        let mailbox = parse_mailbox(r#""Smith, Bob" <bob@example.com>"#).unwrap();
        assert_eq!(mailbox.name.as_deref(), Some("Smith, Bob"));
    }

    #[test]
    fn parse_rejects_non_addresses() {
        assert_eq!(parse_mailbox("Bob Smith"), None);
        assert_eq!(parse_mailbox("@example.com"), None);
        assert_eq!(parse_mailbox("bob@"), None);
        assert_eq!(parse_mailbox(""), None);
    }

    #[test]
    fn serialize_quotes_a_display_name_with_specials() {
        let serialized =
            serialize_address(r#"Smith, Bob <bob@example.com>"#, "alice@1337.legal").unwrap();
        assert_eq!(
            serialized,
            r#""Smith, Bob" <bob_at_example.com_alice@1337.legal>"#
        );
        // Still parses back to the same address.
        assert_eq!(
            deserialize_address(&serialized).unwrap().from,
            "bob@example.com"
        );
    }

    #[test]
    fn serialize_encodes_a_non_ascii_display_name() {
        let serialized = serialize_address("Société <s@example.com>", "alice@1337.legal").unwrap();
        assert!(serialized.starts_with("=?UTF-8?B?"), "{serialized}");
        assert!(
            serialized.ends_with("<s_at_example.com_alice@1337.legal>"),
            "{serialized}"
        );
    }

    #[test]
    fn serialize_strips_header_injection_from_a_display_name() {
        let serialized = serialize_address(
            "Bob\r\nBcc: victim@example.com <bob@example.com>",
            "alice@1337.legal",
        )
        .unwrap();
        assert!(
            !serialized.contains('\r') && !serialized.contains('\n'),
            "{serialized}"
        );
    }

    #[test]
    fn deserialize_rejects_a_plain_alias() {
        assert_eq!(
            deserialize_address("describe-above-crunch@1337.legal"),
            None
        );
    }
}
