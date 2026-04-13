//! Lightweight HTTP health-check server for liveness probes.
//!
//! Exposes a single `GET /healthz` endpoint that returns `200 OK` when the
//! sidecar is running. All other paths return `404 Not Found`.

use std::convert::Infallible;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Minimal HTTP server that serves a `/healthz` liveness probe.
#[derive(Debug)]
pub struct HealthcheckServer {
    listener: TcpListener,
    cancel: CancellationToken,
}

impl HealthcheckServer {
    /// Creates a new health-check server bound to `addr`.
    ///
    /// The server will shut down gracefully when `cancel` is triggered.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP listener cannot bind to `addr`.
    pub async fn bind(addr: SocketAddr, cancel: CancellationToken) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener, cancel })
    }

    /// Runs the accept loop until the cancellation token fires.
    ///
    /// Responds to `GET /healthz` with `200 OK` and rejects every other
    /// request with `404 Not Found`. When the cancellation token fires the
    /// listener stops accepting new connections and in-flight connections are
    /// dropped.
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
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let conn = http1::Builder::new().serve_connection(io, service_fn(handle));
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
async fn handle(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/healthz") => Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from_static(b"ok")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error")))),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error")))),
    };

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, SocketAddrV4};

    /// Starts a health-check server on an OS-assigned port and returns
    /// its bound address together with the cancellation token.
    async fn start_server() -> (SocketAddr, CancellationToken) {
        let cancel = CancellationToken::new();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let server = HealthcheckServer::bind(addr, cancel.clone())
            .await
            .expect("failed to bind ephemeral port");
        let bound = server
            .listener
            .local_addr()
            .expect("failed to get local address");

        tokio::spawn(server.serve());

        (bound, cancel)
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
    async fn healthz_returns_200() {
        let (addr, cancel) = start_server().await;
        let mut sender = connect(addr).await;

        let req = Request::get("/healthz")
            .body(Full::<Bytes>::default())
            .expect("build request");
        let res = sender.send_request(req).await.expect("send request");

        assert_eq!(res.status(), StatusCode::OK);

        cancel.cancel();
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let (addr, cancel) = start_server().await;
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
        let (addr, cancel) = start_server().await;
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
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let server = HealthcheckServer::bind(addr, cancel.clone())
            .await
            .expect("failed to bind");

        let handle = tokio::spawn(server.serve());

        tokio::task::yield_now().await;
        cancel.cancel();

        handle.await.expect("task panicked");
    }
}
