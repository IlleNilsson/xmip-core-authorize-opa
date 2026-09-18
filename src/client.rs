//! The client: where the agent is, and one POST to it over std TCP.

use authorize::AuthorizeError;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// The port an Open Policy Agent listens on where the endpoint names none.
pub const DEFAULT_PORT: u16 = 8181;

/// Where the agent is: `http://host:port`, with an optional base path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    host: String,
    port: u16,
    base: String,
}

impl Endpoint {
    /// Read an endpoint from configuration.
    ///
    /// # Errors
    ///
    /// Refuses anything but `http://`, saying so — this client speaks plain
    /// HTTP/1.1 over std TCP, and an agent that must be reached over TLS is
    /// reached through a local proxy — and refuses an empty host or a port
    /// that is not one.
    pub fn parse(text: &str) -> Result<Self, AuthorizeError> {
        let refused = |why: &str| AuthorizeError::new(format!("the endpoint '{text}' {why}"));

        let rest = text
            .strip_prefix("http://")
            .ok_or_else(|| refused("is not http://, and this client speaks nothing else"))?;
        let (authority, base) = match rest.find('/') {
            Some(at) => (&rest[..at], rest[at..].trim_end_matches('/')),
            None => (rest, ""),
        };

        // `[::1]:8181` keeps its colons inside the brackets.
        let (host, port) = match authority.strip_prefix('[') {
            Some(bracketed) => {
                let (host, after) = bracketed
                    .split_once(']')
                    .ok_or_else(|| refused("opens a bracket it does not close"))?;
                (host, after.strip_prefix(':'))
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };

        if host.is_empty() {
            return Err(refused("names no host"));
        }
        let port = match port {
            Some(port) => port
                .parse()
                .map_err(|_| refused("names a port that is not one"))?,
            None => DEFAULT_PORT,
        };

        Ok(Self {
            host: host.to_string(),
            port,
            base: base.to_string(),
        })
    }

    /// The host, without brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether the agent is on this machine: `localhost`, or an address in
    /// `127.0.0.0/8` or `::1`. A name is never resolved to find out.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self
                .host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    }

    /// POST a JSON body to `path` under the base path and answer with the
    /// response's status and body.
    ///
    /// # Errors
    ///
    /// Refuses where the agent cannot be reached or does not answer within
    /// `timeout`, and where what it answers is not HTTP.
    pub fn post(
        &self,
        path: &str,
        body: &str,
        timeout: Duration,
    ) -> Result<(u16, String), AuthorizeError> {
        let unreachable = |why: &dyn std::fmt::Display| {
            AuthorizeError::new(format!(
                "the agent at {}:{} did not answer: {why}",
                self.host, self.port
            ))
        };

        let mut stream = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|failed| unreachable(&failed))?
            .find_map(|address| TcpStream::connect_timeout(&address, timeout).ok())
            .ok_or_else(|| unreachable(&"no connection"))?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|failed| unreachable(&failed))?;

        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let request = format!(
            "POST {}{path} HTTP/1.1\r\nHost: {host}:{}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            self.base,
            self.port,
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|failed| unreachable(&failed))?;

        // `Connection: close`: the response is everything up to the end.
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|failed| unreachable(&failed))?;

        read_response(&response).map_err(|why| unreachable(&why))
    }
}

/// The status and the body of one HTTP/1.1 response read to its end.
fn read_response(response: &[u8]) -> Result<(u16, String), String> {
    let text = String::from_utf8_lossy(response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or("what came back is not an HTTP response")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1."))
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("what came back has no HTTP status")?;
    let chunked = lines.any(|line| {
        let line = line.to_ascii_lowercase();
        line.starts_with("transfer-encoding:") && line.contains("chunked")
    });

    if chunked {
        Ok((status, unchunk(body)?))
    } else {
        Ok((status, body.to_string()))
    }
}

/// A chunked body, put back together.
fn unchunk(mut body: &str) -> Result<String, String> {
    let mut whole = String::new();

    loop {
        let (size, rest) = body
            .split_once("\r\n")
            .ok_or("a chunked body ends before its last chunk")?;
        let size = size.split(';').next().unwrap_or(size).trim();
        let size = usize::from_str_radix(size, 16)
            .map_err(|_| format!("a chunk size '{size}' is not one"))?;

        if size == 0 {
            return Ok(whole);
        }

        let chunk = rest.get(..size).ok_or("a chunk is shorter than it says")?;
        whole.push_str(chunk);
        body = rest[size..].strip_prefix("\r\n").unwrap_or(&rest[size..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_endpoint_is_a_host_a_port_and_a_base_path() {
        let plain = Endpoint::parse("http://opa.example:8282").expect("an endpoint");
        let based = Endpoint::parse("http://127.0.0.1/opa/").expect("an endpoint");
        let six = Endpoint::parse("http://[::1]:9000").expect("an endpoint");

        assert_eq!((plain.host(), plain.port), ("opa.example", 8282));
        assert_eq!((based.port, based.base.as_str()), (DEFAULT_PORT, "/opa"));
        assert_eq!((six.host(), six.port), ("::1", 9000));
    }

    #[test]
    fn loopback_is_read_off_the_endpoint_and_a_name_is_never_resolved() {
        let loopback = |text: &str| Endpoint::parse(text).expect("an endpoint").is_loopback();

        assert!(loopback("http://127.0.0.1:8181"));
        assert!(loopback("http://127.9.9.9"));
        assert!(loopback("http://localhost:8181"));
        assert!(loopback("http://[::1]:8181"));
        assert!(!loopback("http://opa.example:8181"));
        assert!(!loopback("http://10.0.0.5:8181"));
    }

    #[test]
    fn an_endpoint_this_client_cannot_speak_to_is_refused_saying_why() {
        let refused = |text: &str| Endpoint::parse(text).expect_err("refused").message;

        assert!(refused("https://opa.example").contains("is not http://"));
        assert!(refused("http://:8181").contains("names no host"));
        assert!(refused("http://opa.example:agent").contains("a port that is not one"));
        assert!(refused("http://[::1:8181").contains("bracket"));
    }

    #[test]
    fn a_response_is_a_status_and_a_body_chunked_or_not() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"result\":true}";
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            9\r\n{\"result\"\r\n6\r\n:true}\r\n0\r\n\r\n";

        assert_eq!(
            read_response(plain),
            Ok((200, "{\"result\":true}".to_string()))
        );
        assert_eq!(
            read_response(chunked),
            Ok((200, "{\"result\":true}".to_string()))
        );
        assert_eq!(
            read_response(b"HTTP/1.1 500 Internal Server Error\r\n\r\n").map(|(status, _)| status),
            Ok(500)
        );
        assert!(read_response(b"").is_err());
        assert!(read_response(b"SSH-2.0-OpenSSH\r\n\r\n").is_err());
    }
}
