//! SMTP server entry point.
//!
//! Stands up a samotop SMTP server that only accepts `@1337.legal` recipients
//! and, on `DATA`, captures the message and hands it to [`relay::Relay`] for
//! forwarding.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use relay::config::Config;
use relay::db;
use relay::logs;
use relay::relay::Relay;
use relay::services::mailing::MailingService;

use samotop_core::common::io::Write;
use samotop_core::common::{S1Fut, S2Fut};
use samotop::mail::{
    AcceptsDispatch, AcceptsGuard, AddRecipientFailure, AddRecipientResult, Builder, Configuration,
    DispatchError, DispatchResult, MailDispatch, MailGuard, MailSetup, Name, Recipient,
    StartMailResult,
};
use samotop::io::tls::RustlsProvider;
use samotop::server::TcpServer;
use samotop::smtp::{Esmtp, EsmtpStartTls, SmtpParser, SmtpSession};

mod tls;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Domain the relay accepts recipients for.
const RELAY_DOMAIN: &str = "@1337.legal";

/// The SMTP server's own name (EHLO greeting).
const SERVER_NAME: &str = "mail.1337.legal";

#[async_std::main]
async fn main() -> Result<(), BoxError> {
    // In dev builds, load environment variables from a local `.env` file if
    // present. Release builds rely solely on the real environment.
    #[cfg(debug_assertions)]
    if let Ok(path) = dotenvy::dotenv() {
        logs::info(format!("Loaded environment from {}", path.display()));
    }

    env_logger::init();

    let config = Config::from_env().map_err(|e| -> BoxError { e.into() })?;

    let pool = db::connect(&config.database_url)?;
    let mailing = MailingService::new(&config);
    let relay = Arc::new(Relay::new(pool, mailing));

    let mut service = Builder
        + Name::new(SERVER_NAME)
        + RelayGuard
        + RelayDispatch {
            relay: relay.clone(),
        }
        + Esmtp.with(SmtpParser);

    // Enable STARTTLS when a cert + key are configured.
    match (&config.relay_certificates, &config.relay_private_key) {
        (Some(cert), Some(key)) => {
            let tls_config = tls::load_server_config(cert, key)?;
            let acceptor = async_tls::TlsAcceptor::from(std::sync::Arc::new(tls_config));
            service = service + EsmtpStartTls.with(SmtpParser, RustlsProvider::from(acceptor));
            logs::success("SMTP server with STARTTLS listening on port 25");
        }
        _ => {
            logs::warning("RELAY_CERTIFICATES/RELAY_PRIVATE_KEY not set — STARTTLS disabled");
            logs::success("SMTP server listening on port 25");
        }
    }

    // Defaults to port 25; `RELAY_BIND` overrides for local runs.
    let bind = std::env::var("RELAY_BIND").unwrap_or_else(|_| "0.0.0.0:25".to_owned());
    let result = TcpServer::on(bind).serve(service.build()).await;
    if let Err(err) = &result {
        logs::error(format!("SMTP server error: {err}"));
    }
    result
}

// RCPT guard — only accept `@1337.legal`.

#[derive(Debug)]
struct RelayGuard;

impl MailSetup<Configuration> for RelayGuard {
    fn setup(self, config: &mut Configuration) {
        config.add_last_guard(self);
    }
}

impl MailGuard for RelayGuard {
    fn start_mail<'a, 's, 'f>(&'a self, _session: &'s mut SmtpSession) -> S2Fut<'f, StartMailResult>
    where
        'a: 'f,
        's: 'f,
    {
        // No MAIL FROM restrictions.
        Box::pin(async move { StartMailResult::Accepted })
    }

    fn add_recipient<'a, 's, 'f>(
        &'a self,
        session: &'s mut SmtpSession,
        rcpt: Recipient,
    ) -> S2Fut<'f, AddRecipientResult>
    where
        'a: 'f,
        's: 'f,
    {
        Box::pin(async move {
            let address = rcpt.address.address();
            if address.ends_with(RELAY_DOMAIN) {
                session.transaction.rcpts.push(rcpt);
                AddRecipientResult::Accepted
            } else {
                logs::warning("Only @1337.legal addresses are allowed");
                AddRecipientResult::Failed(
                    AddRecipientFailure::RejectedPermanently,
                    "Only @1337.legal addresses are allowed".to_owned(),
                )
            }
        })
    }
}

// DATA dispatch — capture the message and forward it.

#[derive(Debug)]
struct RelayDispatch {
    relay: Arc<Relay>,
}

impl MailSetup<Configuration> for RelayDispatch {
    fn setup(self, config: &mut Configuration) {
        config.add_last_dispatch(self);
    }
}

impl MailDispatch for RelayDispatch {
    fn open_mail_body<'a, 's, 'f>(
        &'a self,
        session: &'s mut SmtpSession,
    ) -> S1Fut<'f, DispatchResult>
    where
        'a: 'f,
        's: 'f,
    {
        Box::pin(async move {
            // The relay forwards to the first recipient.
            let Some(recipient) = session.transaction.rcpts.first().map(|r| r.address.address())
            else {
                logs::warning("No recipient found in email");
                return Err(DispatchError::Permanent);
            };

            // Install a sink that buffers the DATA bytes and, on close, runs the
            // relay logic; its success/failure becomes the SMTP reply.
            session.transaction.sink = Some(Box::pin(RelaySink {
                relay: self.relay.clone(),
                recipient,
                buf: Vec::new(),
                processing: std::sync::Mutex::new(None),
            }));
            Ok(())
        })
    }
}

/// Async write sink installed on the transaction: accumulates the message body,
/// then processes it when samotop closes the sink after `DATA`.
struct RelaySink {
    relay: Arc<Relay>,
    recipient: String,
    buf: Vec<u8>,
    /// Lazily-created forwarding future, driven to completion by `poll_close`.
    /// Wrapped in a `Mutex` so the sink is `Sync` (required by `MailDataSink`)
    /// even though the forwarding future itself is only `Send`.
    processing:
        std::sync::Mutex<Option<Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>>>,
}

impl std::fmt::Debug for RelaySink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelaySink")
            .field("recipient", &self.recipient)
            .field("bytes", &self.buf.len())
            .finish()
    }
}

impl Write for RelaySink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // On first close, kick off the forwarding work with the buffered body.
        if this.processing.lock().unwrap().is_none() {
            let relay = this.relay.clone();
            let recipient = this.recipient.clone();
            let body = std::mem::take(&mut this.buf);
            *this.processing.lock().unwrap() =
                Some(Box::pin(async move { relay.process(&recipient, &body).await }));
        }

        let mut processing = this.processing.lock().unwrap();
        match processing.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => {
                logs::error(format!("Error parsing or forwarding email: {err}"));
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    err.to_string(),
                )))
            }
        }
    }
}
