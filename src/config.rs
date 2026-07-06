//! Environment configuration.

use std::env;

/// Ensure every named environment variable is present and non-empty.
pub fn check_environment(variables: &[&str]) -> Result<(), String> {
    for variable in variables {
        match env::var(variable) {
            Ok(value) if !value.is_empty() => {}
            _ => return Err(format!("{variable} environment variable is not set")),
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub dkim_domain: String,
    pub dkim_selector: String,
    pub dkim_private_key: String,
    pub relay_certificates: Option<String>,
    pub relay_private_key: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        check_environment(&[
            "DATABASE_URL",
            "DKIM_PRIVATE_KEY",
            "DKIM_DOMAIN",
            "DKIM_SELECTOR",
        ])?;

        Ok(Self {
            database_url: env::var("DATABASE_URL").unwrap(),
            dkim_domain: env::var("DKIM_DOMAIN").unwrap_or_else(|_| "yourdomain.com".into()),
            dkim_selector: env::var("DKIM_SELECTOR").unwrap_or_else(|_| "default".into()),
            dkim_private_key: env::var("DKIM_PRIVATE_KEY")
                .unwrap_or_default()
                .replace("\\n", "\n"),
            relay_certificates: env::var("RELAY_CERTIFICATES").ok().filter(|v| !v.is_empty()),
            relay_private_key: env::var("RELAY_PRIVATE_KEY").ok().filter(|v| !v.is_empty()),
        })
    }
}
