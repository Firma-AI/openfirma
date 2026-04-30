//! Demo fixture CI driver client.
//!
//! Fires `GET /allow` and `POST /deny` through the sidecar HTTP proxy
//! and asserts:
//!
//! - ALLOW: HTTP 200 with body `{"ok":true,"path":"/allow"}`.
//! - DENY:  HTTP 403 with body shape
//!   `{"denied":true,"reason":"...","detail":"..."}`.
//!
//! Exits 0 on success, 1 on the first assertion mismatch with a human
//! readable diagnostic. Used by `make demo-ci` and the `demo-e2e`
//! GitHub Actions job.

use clap::Parser;
use reqwest::Proxy;
use serde::Deserialize;

const SESSION_HEADER: &str = "x-firma-session-id";
const SESSION_VALUE: &str = "demo-session";

#[derive(Parser, Debug)]
#[command(
    name = "firma-demo-fixture-client",
    about = "Drive ALLOW + DENY through the sidecar and assert outcomes"
)]
struct Args {
    /// Sidecar HTTP proxy URL (e.g. `http://127.0.0.1:7474`).
    #[arg(long)]
    proxy: String,
    /// Fixture base URL. Defaults to `http://127.0.0.1:9100`.
    #[arg(long, default_value = "http://127.0.0.1:9100")]
    target: String,
}

#[derive(Debug, Deserialize)]
struct AllowBody {
    ok: bool,
    path: String,
}

#[derive(Debug, Deserialize)]
struct DenyBody {
    denied: bool,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    detail: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = reqwest::Client::builder()
        .proxy(Proxy::all(&args.proxy)?)
        .build()?;

    if let Err(err) = run_allow(&client, &args.target).await {
        eprintln!("[allow] FAIL: {err:#}");
        std::process::exit(1);
    }
    if let Err(err) = run_deny(&client, &args.target).await {
        eprintln!("[deny] FAIL: {err:#}");
        std::process::exit(1);
    }
    println!("[ok] ALLOW + DENY round-trips matched expectation.");
    Ok(())
}

async fn run_allow(client: &reqwest::Client, target: &str) -> anyhow::Result<()> {
    let url = format!("{}/allow", target.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header(SESSION_HEADER, SESSION_VALUE)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    println!("[allow] {status} path=/allow body={body}");
    if status.as_u16() != 200 {
        anyhow::bail!("expected HTTP 200, got {status}; body={body}");
    }
    let parsed: AllowBody = serde_json::from_str(&body).map_err(|e| {
        anyhow::anyhow!("ALLOW body did not parse as expected JSON: {e}; body={body}")
    })?;
    if !parsed.ok {
        anyhow::bail!("ALLOW body had ok=false; body={body}");
    }
    if parsed.path != "/allow" {
        anyhow::bail!(
            "ALLOW body path mismatch: expected /allow, got {}",
            parsed.path
        );
    }
    Ok(())
}

async fn run_deny(client: &reqwest::Client, target: &str) -> anyhow::Result<()> {
    let url = format!("{}/deny", target.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header(SESSION_HEADER, SESSION_VALUE)
        .body("ignored")
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    println!("[deny] {status} path=/deny body={body}");
    if status.as_u16() != 403 {
        anyhow::bail!("expected HTTP 403, got {status}; body={body}");
    }
    let parsed: DenyBody = serde_json::from_str(&body).map_err(|e| {
        anyhow::anyhow!("DENY body did not parse as expected JSON: {e}; body={body}")
    })?;
    if !parsed.denied {
        anyhow::bail!("DENY body did not have denied=true; body={body}");
    }
    if parsed.reason.is_empty() {
        anyhow::bail!("DENY body missing reason; body={body}");
    }
    if parsed.detail.is_empty() {
        anyhow::bail!("DENY body missing detail; body={body}");
    }
    Ok(())
}
