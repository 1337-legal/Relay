//! User lookups and mutations.
#![allow(dead_code)]

use crate::db::models::User;
use sqlx::PgPool;

/// Fields required to insert a new user.
pub struct NewUser {
    pub address: String,
    pub pgp_public_key: Option<String>,
    pub public_key: String,
}

pub async fn find_user_by_id(pool: &PgPool, id: i32) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(r#"SELECT * FROM "User" WHERE "id" = $1 LIMIT 1"#)
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn find_user_by_public_key(
    pool: &PgPool,
    public_key: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(r#"SELECT * FROM "User" WHERE "publicKey" = $1 LIMIT 1"#)
        .bind(public_key)
        .fetch_optional(pool)
        .await
}

pub async fn create_user(pool: &PgPool, data: NewUser) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"INSERT INTO "User" ("address", "pgpPublicKey", "publicKey")
           VALUES ($1, $2, $3)
           RETURNING *"#,
    )
    .bind(data.address)
    .bind(data.pgp_public_key)
    .bind(data.public_key)
    .fetch_optional(pool)
    .await
}

pub async fn delete_user(pool: &PgPool, id: i32) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(r#"DELETE FROM "User" WHERE "id" = $1 RETURNING *"#)
        .bind(id)
        .fetch_all(pool)
        .await
}
