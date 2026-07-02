//! Lightweight HTTP health-check server for readiness probes.
//!
//! Exposes a single `GET /healthz` endpoint that returns `200 OK` after the
//! sidecar has emitted its ready signal. All other paths return
//! `404 Not Found`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Minimal HTTP server that serves a `/healthz` readiness probe.
#[derive(Debug)]
pub struct HealthcheckServer {
    listener: TcpListener,
    cancel: CancellationToken,
    ready: Arc<AtomicBool>,
}

impl HealthcheckServer {
    /// Creates a new health-check server bound to `addr`.
    ///
    /// The server will shut down gracefully when `cancel` is triggered.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP listener cannot bind to `addr`.
    pub async fn bind(
        addr: SocketAddr,
        cancel: CancellationToken,
        ready: Arc<AtomicBool>,
    ) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            cancel,
            ready,
        })
    }

    /// Runs the accept loop until the cancellation token fires.
    ///
    /// Responds to `GET /healthz` with `200 OK` after readiness has been
    /// signalled, `503 Service Unavailable` before readiness, and rejects every
    /// other request with `404 Not Found`. When the cancellation token fires
    /// the listener stops accepting new connections and in-flight connections
    /// are dropped.
    pub async fn serve(self) {
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => {
                    tracing::info!("health server shutting down");
                    return;
                }
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, _remote)) => {
                            self.on_accept(stream);
                        }
                        Err(e) => {
                            tracing::warn!("health server accept error: {e}");
                        }
                    }
                }
            }
        }
    }

    /// Spawns a task to serve a single accepted TCP connection.
    fn on_accept(&self, stream: tokio::net::TcpStream) {
        let cancel = self.cancel.clone();
        let ready = Arc::clone(&self.ready);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let conn = http1::Builder::new().serve_connection(
                io,
                service_fn(move |req| {
                    let response = handle(&req, &ready);
                    std::future::ready(Ok::<Response<Full<Bytes>>, Infallible>(response))
                }),
            );
            tokio::select! {
                biased;
                () = cancel.cancelled() => {}
                result = conn => {
                    if let Err(e) = result {
                        tracing::debug!("health connection error: {e}");
                    }
                }
            }
        });
    }
}

/// Handles a single HTTP request on the health endpoint.
fn handle(req: &Request<hyper::body::Incoming>, ready: &AtomicBool) -> Response<Full<Bytes>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/healthz") if ready.load(Ordering::Acquire) => {
            response(StatusCode::OK, b"ok")
        }
        (&Method::GET, "/healthz") => response(StatusCode::SERVICE_UNAVAILABLE, b"not ready"),
        _ => response(StatusCode::NOT_FOUND, b"not found"),
    }
}

fn response(status: StatusCode, body: &'static [u8]) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

/// Shared readiness flag observed by `/healthz`.
#[must_use]
pub fn readiness_flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// Mark the health endpoint ready.
pub fn mark_ready(ready: &AtomicBool) {
    ready.store(true, Ordering::Release);
}

/// Mark the health endpoint not ready.
pub fn mark_not_ready(ready: &AtomicBool) {
    ready.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, SocketAddrV4};

    /// Starts a health-check server on an OS-assigned port and returns
    /// its bound address together with the cancellation token and readiness
    /// flag.
    async fn start_server() -> (SocketAddr, CancellationToken, Arc<AtomicBool>) {
        let cancel = CancellationToken::new();
        let ready = readiness_flag();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let server = HealthcheckServer::bind(addr, cancel.clone(), Arc::clone(&ready))
            .await
            .expect("failed to bind ephemeral port");
        let bound = server
            .listener
            .local_addr()
            .expect("failed to get local address");

        tokio::spawn(server.serve());

        (bound, cancel, ready)
    }

    /// Creates an HTTP/1 client connection to `addr` and returns the sender.
    async fn connect(addr: SocketAddr) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(
            tokio::net::TcpStream::connect(addr)
                .await
                .expect("connect failed"),
        ))
        .await
        .expect("handshake failed");

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("client conn error: {e}");
            }
        });

        sender
    }

    #[tokio::test]
    async fn healthz_returns_503_before_readiness() {
        let (addr, cancel, _ready) = start_server().await;
        let mut sender = connect(addr).await;

        let req = Request::get("/healthz")
            .body(Full::<Bytes>::default())
            .expect("build request");
        let res = sender.send_request(req).await.expect("send request");

        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

        cancel.cancel();
    }

    #[tokio::test]
    async fn healthz_returns_200_after_readiness() {
        let (addr, cancel, ready) = start_server().await;
        mark_ready(&ready);
        let mut sender = connect(addr).await;

        let req = Request::get("/healthz")
            .body(Full::<Bytes>::default())
            .expect("build request");
        let res = sender.send_request(req).await.expect("send request");

        assert_eq!(res.status(), StatusCode::OK);

        cancel.cancel();
    }

    #[tokio::test]
    async fn healthz_returns_503_after_readiness_is_lost() {
        let (addr, cancel, ready) = start_server().await;
        mark_ready(&ready);
        let mut sender = connect(addr).await;

        let req = Request::get("/healthz")
            .body(Full::<Bytes>::default())
            .expect("build request");
        let res = sender.send_request(req).await.expect("send request");
        assert_eq!(res.status(), StatusCode::OK);
        drop(res);

        mark_not_ready(&ready);
        let req = Request::get("/healthz")
            .body(Full::<Bytes>::default())
            .expect("build request");
        let res = sender.send_request(req).await.expect("send request");

        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

        cancel.cancel();
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let (addr, cancel, _ready) = start_server().await;
        let mut sender = connect(addr).await;

        let req = Request::get("/unknown")
            .body(Full::<Bytes>::default())
            .expect("build request");
        let res = sender.send_request(req).await.expect("send request");

        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        cancel.cancel();
    }

    #[tokio::test]
    async fn post_healthz_returns_404() {
        let (addr, cancel, _ready) = start_server().await;
        let mut sender = connect(addr).await;

        let req = Request::post("/healthz")
            .body(Full::<Bytes>::default())
            .expect("build request");
        let res = sender.send_request(req).await.expect("send request");

        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        cancel.cancel();
    }

    #[tokio::test]
    async fn cancellation_stops_server() {
        let cancel = CancellationToken::new();
        let ready = readiness_flag();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let server = HealthcheckServer::bind(addr, cancel.clone(), ready)
            .await
            .expect("failed to bind");

        let handle = tokio::spawn(server.serve());

        tokio::task::yield_now().await;
        cancel.cancel();

        handle.await.expect("task panicked");
    }
}
