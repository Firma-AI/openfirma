use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

/// A connected broker socket, abstracting over the TCP and Unix transports.
///
/// Shared by the shim-side [`client::BrokerClient`] (outbound connections)
/// and the broker-side [`server::BrokerListener`] (accepted connections). Peer
/// credentials are validated on the concrete socket before it is erased here.
#[pin_project::pin_project(project = BrokerStreamProj)]
pub(crate) enum BrokerStream {
    Tcp {
        #[pin]
        stream: TcpStream,
    },
    #[cfg(unix)]
    Unix {
        #[pin]
        stream: UnixStream,
    },
}

impl AsyncRead for BrokerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.project() {
            BrokerStreamProj::Tcp { stream } => stream.poll_read(cx, buf),
            #[cfg(unix)]
            BrokerStreamProj::Unix { stream } => stream.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BrokerStream {
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp { stream } => stream.is_write_vectored(),
            #[cfg(unix)]
            Self::Unix { stream } => stream.is_write_vectored(),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            BrokerStreamProj::Tcp { stream } => stream.poll_flush(cx),
            #[cfg(unix)]
            BrokerStreamProj::Unix { stream } => stream.poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            BrokerStreamProj::Tcp { stream } => stream.poll_shutdown(cx),
            #[cfg(unix)]
            BrokerStreamProj::Unix { stream } => stream.poll_shutdown(cx),
        }
    }
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            BrokerStreamProj::Tcp { stream } => stream.poll_write(cx, buf),
            #[cfg(unix)]
            BrokerStreamProj::Unix { stream } => stream.poll_write(cx, buf),
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            BrokerStreamProj::Tcp { stream } => stream.poll_write_vectored(cx, bufs),
            #[cfg(unix)]
            BrokerStreamProj::Unix { stream } => stream.poll_write_vectored(cx, bufs),
        }
    }
}
