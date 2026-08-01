use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;

use crate::error::RunError;

#[cfg(any(target_os = "macos", test))]
pub(crate) mod host;

/// Lib-level input for [`execute_dns_stub`]. The CLI layer builds this
/// from its `clap`-derived args struct.
#[derive(Debug, Clone)]
pub struct DnsStubInput {
    /// UDP/TCP DNS listen address reachable by the sandboxed agent process.
    pub listen: SocketAddr,
}

const DNS_HEADER_LEN: usize = 12;
const DNS_RCODE_REFUSED: u8 = 5;

/// Run the internal sandbox-local DNS stub.
///
/// The stub provides an explicit resolver endpoint for structurally confined
/// bwrap sandboxes. It refuses all queries deterministically instead of
/// forwarding to the host ambient resolver.
///
/// # Errors
///
/// Returns an error if UDP or TCP DNS listeners cannot bind.
pub fn execute_dns_stub(args: &DnsStubInput) -> Result<i32, RunError> {
    let udp = UdpSocket::bind(args.listen).map_err(|error| {
        RunError::Spawn(format!(
            "failed to bind sandbox DNS UDP stub at {}: {error}",
            args.listen
        ))
    })?;
    let tcp = TcpListener::bind(args.listen).map_err(|error| {
        RunError::Spawn(format!(
            "failed to bind sandbox DNS TCP stub at {}: {error}",
            args.listen
        ))
    })?;

    thread::Builder::new()
        .name("firma-run-dns-udp".to_string())
        .spawn(move || run_udp(&udp))
        .map_err(|error| RunError::Spawn(format!("failed to spawn DNS UDP stub: {error}")))?;

    run_tcp(&tcp)
}

fn run_udp(socket: &UdpSocket) {
    let mut buf = [0_u8; 4096];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                if let Some(response) = refused_response(&buf[..len]) {
                    let _ = socket.send_to(&response, peer);
                }
            }
            Err(error) => tracing::warn!("DNS UDP stub receive failed: {error}"),
        }
    }
}

fn run_tcp(listener: &TcpListener) -> Result<i32, RunError> {
    loop {
        let (stream, peer) = listener
            .accept()
            .map_err(|error| RunError::Spawn(format!("DNS TCP stub accept failed: {error}")))?;

        thread::spawn(move || {
            if let Err(error) = handle_tcp_client(stream) {
                tracing::warn!("DNS TCP stub connection from {peer} failed: {error}");
            }
        });
    }
}

fn handle_tcp_client(mut stream: TcpStream) -> io::Result<()> {
    loop {
        let mut len_buf = [0_u8; 2];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        let mut query = vec![0_u8; len];
        stream.read_exact(&mut query)?;

        if let Some(response) = refused_response(&query) {
            let len = u16::try_from(response.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS response too large"))?
                .to_be_bytes();
            stream.write_all(&len)?;
            stream.write_all(&response)?;
        }
    }
}

fn refused_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < DNS_HEADER_LEN {
        return None;
    }

    let mut response = query.to_vec();
    response[2] |= 0x80;
    response[3] = (response[3] & 0xF0) | DNS_RCODE_REFUSED;
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    Some(response)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::time::Duration;

    use super::{DNS_RCODE_REFUSED, handle_tcp_client, host::HostDnsStubHandle, refused_response};

    fn sample_query() -> Vec<u8> {
        vec![
            0xAB, 0xCD, // transaction id
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // 1 question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no answers/authority/additional
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ]
    }

    #[test]
    fn refused_response_preserves_query_id_and_question() {
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        let response = refused_response(&query).expect("valid DNS query");

        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_ne!(response[2] & 0x80, 0, "response bit must be set");
        assert_eq!(response[3] & 0x0F, DNS_RCODE_REFUSED);
        assert_eq!(&response[4..6], &[0x00, 0x01]);
        assert_eq!(&response[12..], &query[12..]);
    }

    #[test]
    fn refused_response_rejects_malformed_header() {
        assert!(refused_response(&[0_u8; 11]).is_none());
    }

    #[test]
    fn tcp_client_receives_length_prefixed_refused_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            handle_tcp_client(stream).expect("handle tcp client");
        });

        let mut client = TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let query = sample_query();
        let len = u16::try_from(query.len())
            .expect("sample query fits u16")
            .to_be_bytes();
        client.write_all(&len).expect("write len");
        client.write_all(&query).expect("write query");

        let mut response_len = [0_u8; 2];
        client.read_exact(&mut response_len).expect("read len");
        let response_len = u16::from_be_bytes(response_len) as usize;
        let mut response = vec![0_u8; response_len];
        client.read_exact(&mut response).expect("read response");
        drop(client);
        server.join().expect("server thread");

        assert_eq!(&response[..2], &[0xAB, 0xCD]);
        assert_ne!(response[2] & 0x80, 0, "QR bit must be set");
        assert_eq!(response[3] & 0x0F, DNS_RCODE_REFUSED);
        assert_eq!(&response[12..], &query[12..]);
    }

    #[test]
    fn tcp_client_skips_malformed_query_without_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            handle_tcp_client(stream).expect("handle tcp client");
        });

        let mut client = TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("read timeout");
        client.write_all(&5_u16.to_be_bytes()).expect("write len");
        client.write_all(&[0_u8; 5]).expect("write malformed query");

        let mut response_len = [0_u8; 2];
        let error = client
            .read_exact(&mut response_len)
            .expect_err("malformed query must not produce a TCP response");
        drop(client);
        server.join().expect("server thread");

        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "unexpected read error: {error}"
        );
    }

    // ── HostDnsStubHandle ─────────────────────────────────────────────────────

    #[test]
    fn host_dns_stub_responds_refused_over_udp_and_tcp() {
        let stub = HostDnsStubHandle::start().expect("stub start");
        let addr = stub.listen_addr();

        let client = UdpSocket::bind("127.0.0.1:0").expect("client bind");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");

        let query = sample_query();
        client.send_to(&query, addr).expect("send query");

        let mut buf = [0_u8; 512];
        let (len, _) = client.recv_from(&mut buf).expect("recv response");
        let response = &buf[..len];

        // Transaction ID preserved.
        assert_eq!(&response[..2], &[0xAB, 0xCD]);
        // QR bit set (response).
        assert_ne!(response[2] & 0x80, 0, "QR bit must be set");
        // RCODE = REFUSED.
        assert_eq!(
            response[3] & 0x0F,
            DNS_RCODE_REFUSED,
            "RCODE must be REFUSED"
        );

        let mut tcp_client = TcpStream::connect(addr).expect("TCP connect");
        tcp_client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set TCP timeout");
        tcp_client
            .write_all(
                &u16::try_from(query.len())
                    .expect("query fits u16")
                    .to_be_bytes(),
            )
            .expect("write TCP query length");
        tcp_client.write_all(&query).expect("write TCP query");

        let mut response_len = [0_u8; 2];
        tcp_client
            .read_exact(&mut response_len)
            .expect("read TCP response length");
        let mut response = vec![0_u8; u16::from_be_bytes(response_len) as usize];
        tcp_client
            .read_exact(&mut response)
            .expect("read TCP response");
        assert_eq!(&response[..2], &[0xAB, 0xCD]);
        assert_ne!(response[2] & 0x80, 0, "QR bit must be set");
        assert_eq!(response[3] & 0x0F, DNS_RCODE_REFUSED);
    }

    #[test]
    fn host_dns_stub_drops_cleanly() {
        let stub = HostDnsStubHandle::start().expect("stub start");
        let addr = stub.listen_addr();
        drop(stub);
        // After drop the port should be released; a new stub can bind there if
        // the OS reuses ephemeral ports — or just verify it doesn't hang.
        let _ = addr;
    }

    #[test]
    fn host_dns_stub_listen_addr_is_loopback() {
        let stub = HostDnsStubHandle::start().expect("stub start");
        assert_eq!(
            stub.listen_addr().ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "stub must bind on loopback"
        );
    }
}
