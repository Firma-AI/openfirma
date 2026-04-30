//! Demo fixture server binary.
//!
//! Hyper 1.x server bound to `127.0.0.1:9100` by default. Routes:
//!
//! | Method + path  | Status | Body                              |
//! |----------------|--------|-----------------------------------|
//! | `GET /allow`   | 200    | `{"ok":true,"path":"/allow"}`     |
//! | `POST /deny`   | 200    | `{"would":"leak"}`                |
//! | `GET /_ping`   | 200    | `ok`                              |
//! | other          | 404    | `not found`                       |
//!
//! The sidecar denies `POST /deny` upstream so the server's response
//! shape on that route is only consulted as a positive control if the
//! demo policy is broken.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use openauthority_demo_fixture::{
    ALLOW_BODY_JSON, DEFAULT_LISTEN_ADDR, DENY_BODY_JSON, PING_BODY_TEXT,
};
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(
    name = "openauthority-demo-fixture",
    about = "Deterministic ALLOW/DENY fixture server for the OpenAuthority demo CI gate"
)]
struct Args {
    /// Address to bind. Defaults to `127.0.0.1:9100`.
    #[arg(long, default_value = DEFAULT_LISTEN_ADDR)]
    listen_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args = Args::parse();
    let listener = TcpListener::bind(args.listen_addr).await?;
    let bound = listener.local_addr()?;
    tracing::info!(addr = %bound, "openauthority-demo-fixture listening");

    let builder = Arc::new(Builder::new(TokioExecutor::new()));
    loop {
        let (stream, peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let builder = Arc::clone(&builder);
        tokio::spawn(async move {
            if let Err(err) = builder.serve_connection(io, service_fn(handle)).await {
                tracing::debug!(?peer, error = %err, "connection closed with error");
            }
        });
    }
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/allow") => json_response(StatusCode::OK, ALLOW_BODY_JSON),
        (&Method::POST, "/deny") => json_response(StatusCode::OK, DENY_BODY_JSON),
        (&Method::GET, "/_ping") => text_response(StatusCode::OK, PING_BODY_TEXT),
        _ => text_response(StatusCode::NOT_FOUND, "not found"),
    };
    Ok(response)
}

fn json_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    build_response(status, HeaderValue::from_static("application/json"), body)
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    build_response(
        status,
        HeaderValue::from_static("text/plain; charset=utf-8"),
        body,
    )
}

fn build_response(
    status: StatusCode,
    content_type: HeaderValue,
    body: &'static str,
) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(CONTENT_TYPE, content_type);
    response
}
