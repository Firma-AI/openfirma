use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;

use crate::args::DnsStubArgs;
use crate::error::RunError;

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
pub fn execute_dns_stub(args: &DnsStubArgs) -> Result<i32, RunError> {
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
    use super::{DNS_RCODE_REFUSED, refused_response};

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
}
