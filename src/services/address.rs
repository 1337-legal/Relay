//! Alias address (de)serialization.
//!
//! Encodes an original sender + alias into a single reply-able relay address and
//! back again, using the `_at_` and `_` separators.

use once_cell::sync::Lazy;
use regex::Regex;

/// Parses `Display <addr>` or a bare address.
static SERIALIZE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:(.+?)\s*<([^>]+)>|([^<>\s]+))$").unwrap());

/// Extracts the address from `Display <addr>` or a bare address.
static DESERIALIZE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"<([^>]+)>|([^<>\s]+)$").unwrap());

/// The original address paired with its alias, recovered from a relay address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deserialized {
    pub from: String,
    pub alias: String,
}

/// Everything after the first `@`, or `None` when there is no domain.
pub fn get_domain_from_email(email: &str) -> Option<String> {
    email.split_once('@').map(|(_, domain)| domain.to_string())
}

/// Serialize an original sender + alias into a single relay-back address.
///
/// `("bob@example.com", "alice@1337.legal")` →
/// `"bob_at_example.com_alice@1337.legal"`. A display name is preserved:
/// `"Bob <bob@example.com>"` → `"Bob <bob_at_...@1337.legal>"`.
pub fn serialize_address(from: &str, alias: &str) -> Option<String> {
    let caps = SERIALIZE_RE.captures(from.trim())?;

    let display_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let original_from = caps
        .get(2)
        .or_else(|| caps.get(3))
        .map(|m| m.as_str())
        .filter(|s| !s.is_empty())?;

    let recipient_domain = get_domain_from_email(alias)?;
    let alias_local = alias.split('@').next().unwrap_or("");

    let serialized = format!(
        "{}_{}@{}",
        original_from.replace('@', "_at_"),
        alias_local,
        recipient_domain
    );

    Some(if display_name.is_empty() {
        serialized
    } else {
        format!("{display_name} <{serialized}>")
    })
}

/// Reverse [`serialize_address`], recovering the original sender and alias.
///
/// `"bob_at_example.com_alice@1337.legal"` →
/// `{ from: "bob@example.com", alias: "alice@1337.legal" }`.
pub fn deserialize_address(serialized: &str) -> Option<Deserialized> {
    let caps = DESERIALIZE_RE.captures(serialized.trim())?;

    let email_part = caps
        .get(1)
        .or_else(|| caps.get(2))
        .map(|m| m.as_str())
        .filter(|s| !s.is_empty())?;

    let at_index = email_part.rfind('@')?;
    let local_part = &email_part[..at_index];
    let domain = &email_part[at_index + 1..];

    // The alias local-part is whatever follows the final underscore.
    let last_underscore = local_part.rfind('_')?;
    let alias_local = &local_part[last_underscore + 1..];
    let encoded_original = &local_part[..last_underscore];

    let original_from = encoded_original.replace("_at_", "@");
    let alias = format!("{alias_local}@{domain}");

    Some(Deserialized {
        from: original_from,
        alias,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
