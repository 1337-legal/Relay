# 1337.legal

**1337.legal** is a privacy-first, encrypted email alias relay service inspired by DuckDuckGo Email Protection, but with a hacker twist. Protect your real email address, forward messages securely, and keep your inbox 1337.

---

## 🚀 Features

-   **Anonymous Email Aliases:** Generate unique aliases to shield your real email address.
-   **End-to-End Encryption:** All forwarded emails are encrypted with your PGP public key before delivery.
-   **Custom Forwarding:** Choose where your emails are sent—your real inbox stays hidden.
-   **Blazing Fast:** Built with [Rust](https://www.rust-lang.org/), [samotop](https://docs.rs/samotop), and [Postgres](https://www.postgresql.org/) for speed and safety.

---

## 🛠️ Getting Started

### 1. Clone the Repo

```sh
git clone https://github.com/1337-legal/Relay.git
cd Relay
```

### 2. Configure

Copy `.env.example` to `.env` and fill in `DATABASE_URL`, the `DKIM_*` keys, and (optionally) `RELAY_CERTIFICATES` / `RELAY_PRIVATE_KEY` for STARTTLS.

### 3. Run

```sh
docker compose up --build      # relay + Postgres
# or
cargo run                      # loads .env in dev
```

The relay listens for SMTP on port `25` (override with `RELAY_BIND`).
