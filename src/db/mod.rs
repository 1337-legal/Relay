//! Postgres connection pool.

pub mod models;

use sqlx::postgres::{PgPool, PgPoolOptions};

/// Create the shared Postgres connection pool.
///
/// The pool is lazy — no connection is opened until the first query, so the
/// server starts even if the database is briefly unavailable.
pub fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect_lazy(database_url)
}
