#![warn(missing_docs)]
#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
//! An implementation of the multiaddr network address standard.

use std::{str, fmt, error};
use std::net::{Ipv4Addr, Ipv6Addr, AddrParseError};
use std::num::ParseIntError;

/// An individual component of a `Multiaddr`.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum Addr {
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address.
    Ipv6(Ipv6Addr),
    /// A TCP port.
    Tcp(u16),
    /// A UDP port.
    Udp(u16),
    /// An IPFS peer ID.
    Ipfs(String),
}

use Addr::*;

impl Addr {
    /// Returns true if this is an IPv4 address.
    pub fn is_ipv4(&self) -> bool {
        match *self {
            Ipv4(_) => true,
            _ => false,
        }
    }

    /// Returns true if this is an IPv6 address.
    pub fn is_ipv6(&self) -> bool {
        match *self {
            Ipv6(_) => true,
            _ => false,
        }
    }

    /// Returns true if this is a TCP port.
    pub fn is_tcp(&self) -> bool {
        match *self {
            Tcp(_) => true,
            _ => false,
        }
    }

    /// Returns true if this is a UDP port.
    pub fn is_udp(&self) -> bool {
        match *self {
            Udp(_) => true,
            _ => false,
        }
    }

    /// Returns true if this is an IPFS peer ID.
    pub fn is_ipfs(&self) -> bool {
        match *self {
            Ipfs(_) => true,
            _ => false,
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Ipv4(addr) => write!(f, "/ip4/{}", addr),
            Ipv6(addr) => write!(f, "/ip6/{}", addr),
            Tcp(port) => write!(f, "/tcp/{}", port),
            Udp(port) => write!(f, "/udp/{}", port),
            Ipfs(ref id) => write!(f, "/ipfs/{}", id),
        }
    }
}

/// A multiaddr compatible network address.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Multiaddr {
    parts: Vec<Addr>,
}

impl Multiaddr {
    /// Creates an empty `Multiaddr`.
    pub fn new() -> Multiaddr {
        Multiaddr { parts: Vec::new() }
    }

    /// Creates a `Multiaddr` from a series of address parts.
    pub fn from_parts(parts: Vec<Addr>) -> Multiaddr {
        Multiaddr { parts: parts }
    }

    /// Gets an ordered list of address parts.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::{Multiaddr, Addr};
    ///
    /// let ma = "/ip6/2001:db8:85a3::39/tcp/80".parse::<Multiaddr>().unwrap();
    /// assert_eq!(ma.parts().len(), 2);
    /// assert_eq!(ma.parts()[1], Addr::Tcp(80));
    /// ```
    pub fn parts(&self) -> &Vec<Addr> {
        &self.parts
    }

    /// Wraps `other`.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let foo = "/ip4/127.0.0.1/tcp/1723".parse::<Multiaddr>().unwrap();
    /// let bar = "/ip4/1.2.3.4/udp/30".parse::<Multiaddr>().unwrap();
    /// let proxied = foo.encapsulate(&bar);
    /// assert_eq!(proxied.to_string(),
    ///            "/ip4/127.0.0.1/tcp/1723/ip4/1.2.3.4/udp/30");
    /// ```
    pub fn encapsulate(&self, other: &Multiaddr) -> Multiaddr {
        let mut new = self.clone();
        new.encapsulate_mut(other);
        new
    }

    /// Wraps `other`, in place.
    pub fn encapsulate_mut(&mut self, other: &Multiaddr) {
        self.parts.extend_from_slice(&other.parts[..]);
    }

    /// Returns true if the multiaddr doesn't contain any address parts.
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Returns true if the multiaddr contains at least one IPv4 part.
    pub fn contains_ipv4(&self) -> bool {
        self.parts.iter().any(Addr::is_ipv4)
    }

    /// Returns true if the multiaddr contains at least one IPv6 part.
    pub fn contains_ipv6(&self) -> bool {
        self.parts.iter().any(Addr::is_ipv6)
    }

    /// Returns true if the multiaddr contains at least one TCP part.
    pub fn contains_tcp(&self) -> bool {
        self.parts.iter().any(Addr::is_tcp)
    }

    /// Returns true if the multiaddr contains at least one UDP part.
    pub fn contains_udp(&self) -> bool {
        self.parts.iter().any(Addr::is_udp)
    }

    /// Returns true if the multiaddr contains at least one IPFS part.
    pub fn contains_ipfs(&self) -> bool {
        self.parts.iter().any(Addr::is_ipfs)
    }
}

impl fmt::Display for Multiaddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_empty() {
            try!(write!(f, "/"));
        } else {
            for part in &self.parts {
                try!(part.fmt(f));
            }
        }
        Ok(())
    }
}

/// An error returned when parsing a `Multiaddr`.
#[derive(Debug, PartialEq, Clone)]
pub enum MultiaddrParseError {
    /// A chunk was missing.
    MissingChunk(String),
    /// An invalid protocol was encountered.
    InvalidProtocol(String),
    /// An invalid IPv4 or IPv6 address was encountered.
    InvalidIp(AddrParseError),
    /// An invalid TCP or UDP port was encountered.
    InvalidPort(ParseIntError),
}

pub use MultiaddrParseError::*;

impl fmt::Display for MultiaddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MissingChunk(ref c) => {
                write!(f, "missing address chunk of type '{}'", c)
            }
            InvalidProtocol(ref p) => write!(f, "invalid protocol '{}'", p),
            InvalidIp(ref err) => err.fmt(f),
            InvalidPort(ref err) => err.fmt(f),
        }
    }
}

impl error::Error for MultiaddrParseError {
    fn description(&self) -> &str {
        match *self {
            MissingChunk(_) => "missing address chunk",
            InvalidProtocol(_) => "invalid protocol",
            InvalidIp(_) => "invalid ip address",
            InvalidPort(_) => "invalid port number",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            InvalidIp(ref err) => Some(err),
            InvalidPort(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<AddrParseError> for MultiaddrParseError {
    fn from(err: AddrParseError) -> MultiaddrParseError {
        InvalidIp(err)
    }
}

impl From<ParseIntError> for MultiaddrParseError {
    fn from(err: ParseIntError) -> MultiaddrParseError {
        InvalidPort(err)
    }
}

impl str::FromStr for Multiaddr {
    type Err = MultiaddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = Vec::new();
        let mut split = s.split('/').skip(1);

        while let Some(typ) = split.next() {
            if typ.is_empty() {
                // Allow a trailing / but don't allow consecutive /'s
                // in the middle of an address
                if split.count() == 0 {
                    break;
                }
                return Err(MissingChunk("protocol descriptor".to_owned()));
            }

            if let Some(addr) = split.next() {
                if addr.is_empty() {
                    return Err(MissingChunk(typ.to_owned()));
                }

                match typ {
                    "ip4" => {
                        let ip4 = try!(addr.parse::<Ipv4Addr>());
                        parts.push(Ipv4(ip4));
                    }
                    "ip6" => {
                        let ip6 = try!(addr.parse::<Ipv6Addr>());
                        parts.push(Ipv6(ip6));
                    }
                    "tcp" => {
                        let port = try!(addr.parse::<u16>());
                        parts.push(Tcp(port));
                    }
                    "udp" => {
                        let port = try!(addr.parse::<u16>());
                        parts.push(Udp(port));
                    }
                    "ipfs" => parts.push(Ipfs(addr.to_owned())),
                    _ => {
                        return Err(InvalidProtocol(typ.to_owned()));
                    }
                }
            } else {
                return Err(MissingChunk(typ.to_owned()));
            }
        }
        Ok(Multiaddr::from_parts(parts))
    }
}

#[cfg(test)]
mod tests {
    use super::{Multiaddr, Addr, InvalidPort, InvalidProtocol, InvalidIp,
                MissingChunk};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn parses_empty_address() {
        // Should we even allow empty addresses?
        let parsed = Multiaddr::from_str("").unwrap();
        assert!(parsed.is_empty());
        assert_eq!(parsed.to_string(), "/");

        let parsed = Multiaddr::from_str("/").unwrap();
        assert!(parsed.is_empty());
        assert_eq!(parsed.to_string(), "/");
    }

    #[test]
    fn parses_ipv4_address() {
        let ip4 = Ipv4Addr::from_str("127.0.0.1").unwrap();
        let ma = Multiaddr::from_parts(vec![Addr::Ipv4(ip4)]);
        let parsed = Multiaddr::from_str("/ip4/127.0.0.1").unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.to_string(), "/ip4/127.0.0.1");
    }

    #[test]
    fn parses_ipv6_address() {
        let ip6 = Ipv6Addr::from_str("2001:DB8:AC10::1").unwrap();
        let ma = Multiaddr::from_parts(vec![Addr::Ipv6(ip6)]);
        let parsed = Multiaddr::from_str("/ip6/2001:DB8:AC10::1").unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.to_string(), "/ip6/2001:db8:ac10::1");
    }

    #[test]
    fn parses_tcp_address() {
        let ma = Multiaddr::from_parts(vec![Addr::Tcp(80)]);
        let parsed = Multiaddr::from_str("/tcp/80").unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.to_string(), "/tcp/80");
    }

    #[test]
    fn parses_udp_address() {
        let ma = Multiaddr::from_parts(vec![Addr::Udp(5001)]);
        let parsed = Multiaddr::from_str("/udp/5001").unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.to_string(), "/udp/5001");
    }

    #[test]
    fn parses_ipfs_address() {
        let id = "QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm".to_owned();
        let ma = Multiaddr::from_parts(vec![Addr::Ipfs(id)]);
        let parsed = Multiaddr::from_str("/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKW\
                                          crNFTDAadQJmocnWm")
                         .unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.to_string(),
                   "/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm");
    }


    #[test]
    fn parses_mixed_address() {
        let ip4 = Ipv4Addr::from_str("127.0.0.1").unwrap();
        let ip6 = Ipv6Addr::from_str("::1").unwrap();
        let ma = Multiaddr::from_parts(vec![Addr::Ipv4(ip4),
                                            Addr::Udp(64),
                                            Addr::Ipv6(ip6)]);
        let parsed = Multiaddr::from_str("/ip4/127.0.0.1/udp/64/ip6/::1/")
                         .unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.to_string(), "/ip4/127.0.0.1/udp/64/ip6/::1");
    }

    #[test]
    fn fails_parse_invalid_protocol() {
        match Multiaddr::from_str("/foo/255.255.255.0") {
            Err(InvalidProtocol(_)) => {}
            _ => panic!("shouldn't parse protocol 'foo'"),
        }
    }

    #[test]
    fn fails_parse_missing_chunk() {
        match Multiaddr::from_str("/ip4/") {
            Err(MissingChunk(_)) => {}
            _ => panic!("shouldn't parse address with missing chunk"),
        }

        match Multiaddr::from_str("/ip4/127.0.0.1//udp/39") {
            Err(MissingChunk(_)) => {}
            _ => panic!("shouldn't parse address with missing chunk"),
        }
    }

    #[test]
    fn fails_parse_invalid_ip() {
        match Multiaddr::from_str("/ip6/google.com/tcp/80") {
            Err(InvalidIp(_)) => {}
            _ => panic!("shouldn't parse invalid ip address"),
        }

        match Multiaddr::from_str("/ip4/700.256.29.40") {
            Err(InvalidIp(_)) => {}
            _ => panic!("shouldn't parse invalid ip address"),
        }

        match Multiaddr::from_str("/ip4/1.2.3.4.5") {
            Err(InvalidIp(_)) => {}
            _ => panic!("shouldn't parse invalid ip address"),
        }

        match Multiaddr::from_str("/ip6/:::") {
            Err(InvalidIp(_)) => {}
            _ => panic!("shouldn't parse invalid ip address"),
        }
    }

    #[test]
    fn fails_parse_negative_port() {
        match Multiaddr::from_str("/udp/-39") {
            Err(InvalidPort(_)) => {}
            _ => panic!("shouldn't parse /udp/-39"),
        }
    }

    #[test]
    fn fails_parse_overflow_port() {
        match Multiaddr::from_str("/udp/65536") {
            Err(InvalidPort(_)) => {}
            _ => panic!("shouldn't parse /udp/65536 (overflow)"),
        }
    }
}
