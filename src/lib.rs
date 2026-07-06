//! A privacy-first, PGP-encrypting email alias relay.
//!
//! Incoming mail to an `@1337.legal` alias is looked up in Postgres, its sender
//! is rewritten into a reply-able relay address, the body is optionally
//! PGP-encrypted to the user's key, and it is forwarded to the user's real
//! inbox. Replies sent back to a serialized relay address are decoded and
//! delivered to the original sender.

pub mod config;
pub mod db;
pub mod relay;
pub mod repositories;
pub mod services;

#[path = "lib/logs.rs"]
pub mod logs;
