//! OpenPGP encryption.

use anyhow::{Context, Result};
use pgp::composed::{Deserializable, Message, SignedPublicKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;

/// Encrypt `email_content` to the given armored public key, returning an
/// ASCII-armored OpenPGP message.
pub fn encrypt_email_content(email_content: &str, armored_public_key: &str) -> Result<String> {
    let (public_key, _headers) = SignedPublicKey::from_string(armored_public_key)
        .context("failed to parse armored public key")?;

    let message = Message::new_literal("", email_content);
    let mut rng = rand::thread_rng();

    // Prefer an encryption subkey when present, falling back to the primary key.
    let encrypted = if let Some(subkey) = public_key.public_subkeys.first() {
        message.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES256, &[subkey])
    } else {
        message.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES256, &[&public_key])
    }
    .context("PGP encryption failed")?;

    encrypted
        .to_armored_string(Default::default())
        .context("failed to armor encrypted message")
}

/// Whether `armored_public_key` parses as a valid public key.
pub fn is_valid_public_key(armored_public_key: &str) -> bool {
    SignedPublicKey::from_string(armored_public_key).is_ok()
}
