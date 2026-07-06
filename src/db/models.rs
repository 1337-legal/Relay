//! Database row models.
//!
//! Column names are camelCase and table names PascalCase, so the `sqlx` field
//! renames below map the snake_case fields onto the real columns.

use sqlx::FromRow;

/// An account that receives forwarded mail.
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: i32,
    /// The user's real (hidden) forwarding address.
    pub address: String,
    /// Optional armored PGP public key used to encrypt forwarded mail.
    #[sqlx(rename = "pgpPublicKey")]
    pub pgp_public_key: Option<String>,
    #[sqlx(rename = "publicKey")]
    pub public_key: String,
    /// `"guest"` or `"user"`.
    pub role: String,
}

/// A public relay address bound to a user.
#[derive(Debug, Clone, FromRow)]
pub struct Alias {
    pub id: i32,
    #[sqlx(rename = "userId")]
    pub user_id: i32,
    pub address: String,
    /// `"active"` or `"disabled"`.
    pub status: String,
}
