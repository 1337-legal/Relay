//! Alias lookups.

use crate::db::models::{Alias, User};
use sqlx::PgPool;

/// Fetch the user that owns a given alias address, joining `Alias` → `User`.
pub async fn get_user_by_alias(pool: &PgPool, alias: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"SELECT "User".*
           FROM "Alias"
           INNER JOIN "User" ON "Alias"."userId" = "User"."id"
           WHERE "Alias"."address" = $1
           LIMIT 1"#,
    )
    .bind(alias)
    .fetch_optional(pool)
    .await
}

/// Fetch an alias row by its address.
pub async fn get_alias_by_address(
    pool: &PgPool,
    address: &str,
) -> Result<Option<Alias>, sqlx::Error> {
    sqlx::query_as::<_, Alias>(
        r#"SELECT * FROM "Alias" WHERE "address" = $1 LIMIT 1"#,
    )
    .bind(address)
    .fetch_optional(pool)
    .await
}
