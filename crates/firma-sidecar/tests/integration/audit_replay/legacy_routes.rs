//! Simulates a collector whose router has no evidence-aware RPC. Rejection
//! happens before protobuf decoding, as it does on a server built from the old schema.

use std::convert::Infallible;
use std::task::{Context, Poll};

use tonic::body::Body;
use tonic::codegen::BoxFuture;
use tonic::server::NamedService;
use tower::Service;

#[derive(Clone)]
pub struct Routes<S> {
    pub inner: S,
    pub legacy_only: bool,
    pub unsupported: tokio::sync::mpsc::UnboundedSender<()>,
}

impl<S: NamedService> NamedService for Routes<S> {
    const NAME: &'static str = S::NAME;
}

impl<S> Service<http::Request<Body>> for Routes<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>,
    S::Future: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        if self.legacy_only && request.uri().path() != "/firma.v1.AuditService/StreamEvents" {
            let _ = self.unsupported.send(());
            return Box::pin(async {
                Ok(tonic::Status::unimplemented("unknown audit RPC").into_http())
            });
        }
        Box::pin(self.inner.call(request))
    }
}
