#![warn(missing_docs)]
#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
//! An implementation of the [multiaddr](https://github.com/jbenet/multiaddr)
//! network address standard.

extern crate rust_base58;

mod varint;

use std::{str, fmt, error, mem};
use std::io::{Read, Write, Cursor, Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, AddrParseError};
use std::num::ParseIntError;

use rust_base58::{FromBase58, ToBase58};

use varint::{write_varint_u64, read_varint_u64};

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
    /// A DCCP port.
    Dccp(u16),
    /// An SCTP port.
    Sctp(u16),
    /// An IPFS peer ID.
    Ipfs(String),
    /// An HTTP reference
    Http,
    /// An HTTPS reference.
    Https,
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

    /// Returns ture if this is a DCCP port.
    pub fn is_dccp(&self) -> bool {
        match *self {
            Dccp(_) => true,
            _ => false,
        }
    }

    /// Returns true if this is an SCTP port.
    pub fn is_sctp(&self) -> bool {
        match *self {
            Sctp(_) => true,
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

    /// Returns true if this is an HTTP reference.
    pub fn is_http(&self) -> bool {
        match *self {
            Http => true,
            _ => false,
        }
    }

    /// Returns true if this is an HTTPS reference.
    pub fn is_https(&self) -> bool {
        match *self {
            Https => true,
            _ => false,
        }
    }

    fn write<T: Write>(&self, w: &mut T) -> Result<(), Error> {
        match *self {
            Ipv4(ip) => {
                try!(write_varint_u64(w, 4));
                w.write_all(&ip.octets()[..])
            }
            Ipv6(ip) => {
                try!(write_varint_u64(w, 41));
                let segments = ip.segments();
                unsafe {
                    let bytes = mem::transmute::<[u16; 8], [u8; 16]>(segments);
                    w.write_all(&bytes[..])
                }
            }
            Tcp(port) => {
                try!(write_varint_u64(w, 6));
                let bytes: [u8; 2] = [(port >> 8) as u8, (port & 0xFF) as u8];
                w.write_all(&bytes)
            }
            Udp(port) => {
                try!(write_varint_u64(w, 17));
                let bytes: [u8; 2] = [(port >> 8) as u8, (port & 0xFF) as u8];
                w.write_all(&bytes)
            }
            Dccp(port) => {
                try!(write_varint_u64(w, 33));
                let bytes: [u8; 2] = [(port >> 8) as u8, (port & 0xFF) as u8];
                w.write_all(&bytes)
            }
            Sctp(port) => {
                try!(write_varint_u64(w, 132));
                let bytes: [u8; 2] = [(port >> 8) as u8, (port & 0xFF) as u8];
                w.write_all(&bytes)
            }
            Ipfs(ref addr) => {
                try!(write_varint_u64(w, 421));
                if let Ok(bytes) = addr.from_base58() {
                    try!(write_varint_u64(w, bytes.len() as u64));
                    w.write_all(&bytes[..])
                } else {
                    Err(Error::new(ErrorKind::InvalidData, "invalid base58"))
                }
            }
            Http => write_varint_u64(w, 480),
            Https => write_varint_u64(w, 443),
        }
    }

    fn read<T: Read>(r: &mut T) -> Result<Addr, Error> {
        let code = try!(read_varint_u64(r));
        match code {
            4 => {
                let mut bytes = [0; 4];
                try!(r.read_exact(&mut bytes[..]));
                let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                Ok(Ipv4(ip))
            }
            41 => {
                let mut bytes = [0; 16];
                try!(r.read_exact(&mut bytes[..]));
                let segments: [u16; 8] = unsafe {
                    mem::transmute::<[u8; 16], [u16; 8]>(bytes)
                };
                let ip = Ipv6Addr::new(segments[0],
                                       segments[1],
                                       segments[2],
                                       segments[3],
                                       segments[4],
                                       segments[5],
                                       segments[6],
                                       segments[7]);
                Ok(Ipv6(ip))
            }
            6 => {
                let mut bytes = [0; 2];
                try!(r.read_exact(&mut bytes[..]));
                let port = (bytes[0] as u16) << 8 | bytes[1] as u16;
                Ok(Tcp(port))
            }
            17 => {
                let mut bytes = [0; 2];
                try!(r.read_exact(&mut bytes[..]));
                let port = (bytes[0] as u16) << 8 | bytes[1] as u16;
                Ok(Udp(port))
            }
            33 => {
                let mut bytes = [0; 2];
                try!(r.read_exact(&mut bytes[..]));
                let port = (bytes[0] as u16) << 8 | bytes[1] as u16;
                Ok(Dccp(port))
            }
            132 => {
                let mut bytes = [0; 2];
                try!(r.read_exact(&mut bytes[..]));
                let port = (bytes[0] as u16) << 8 | bytes[1] as u16;
                Ok(Sctp(port))
            }
            421 => {
                let len = try!(read_varint_u64(r));
                let mut bytes = vec![0; len as usize];
                try!(r.read_exact(&mut bytes[..]));
                let addr = bytes.to_base58();
                Ok(Ipfs(addr))
            }
            480 => Ok(Http),
            483 => Ok(Https),
            _ => {
                Err(Error::new(ErrorKind::InvalidData,
                               format!("bad protocol code: {}", code)))
            }
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
            Dccp(port) => write!(f, "/dccp/{}", port),
            Sctp(port) => write!(f, "/sctp/{}", port),
            Ipfs(ref id) => write!(f, "/ipfs/{}", id),
            Http => write!(f, "/http"),
            Https => write!(f, "/https"),
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

    /// Writes a multiaddr in the standard binary encoding scheme.
    pub fn write<T: Write>(&self, w: &mut T) -> Result<(), Error> {
        for part in &self.parts {
            try!(part.write(w));
        }
        Ok(())
    }

    /// Encodes a multiaddr to the standard binary encoding scheme.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Cursor::new(Vec::new());
        try!(self.write(&mut buf));
        Ok(buf.into_inner())
    }

    /// Decodes a multiaddr encoded in the standard binary encoding scheme.
    pub fn from_bytes(buf: &[u8]) -> Result<Multiaddr, Error> {
        let len = buf.len();
        let mut cursor = Cursor::new(buf);
        let mut parts = Vec::new();
        while cursor.position() < len as u64 {
            let part = try!(Addr::read(&mut cursor));
            parts.push(part);
        }
        Ok(Multiaddr { parts: parts })
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

    /// Returns true if the multiaddr contains at least one DCCP part.
    pub fn contains_dccp(&self) -> bool {
        self.parts.iter().any(Addr::is_dccp)
    }

    /// Returns true if the multiaddr contains at least one SCTP part.
    pub fn contains_sctp(&self) -> bool {
        self.parts.iter().any(Addr::is_sctp)
    }

    /// Returns true if the multiaddr contains at least one IPFS part.
    pub fn contains_ipfs(&self) -> bool {
        self.parts.iter().any(Addr::is_ipfs)
    }

    /// Returns true if the multiaddr contains at least one HTTP part.
    pub fn contains_http(&self) -> bool {
        self.parts.iter().any(Addr::is_http)
    }

    /// Returns true if the multiaddr contains at least one HTTPS part.
    pub fn contains_https(&self) -> bool {
        self.parts.iter().any(Addr::is_https)
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

use MultiaddrParseError::*;

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

            if typ == "http" {
                parts.push(Http);
                continue;
            }

            if typ == "https" {
                parts.push(Https);
                continue;
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
                    "dccp" => {
                        let port = try!(addr.parse::<u16>());
                        parts.push(Dccp(port));
                    }
                    "sctp" => {
                        let port = try!(addr.parse::<u16>());
                        parts.push(Sctp(port));
                    }
                    // TODO: do some validation on the IPFS hash
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
    use super::{Multiaddr, Addr};
    use super::MultiaddrParseError::*;
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
    fn parses_dccp_address() {
        let ma = Multiaddr::from_parts(vec![Addr::Dccp(593)]);
        let parsed = Multiaddr::from_str("/dccp/593").unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.to_string(), "/dccp/593");
    }

    #[test]
    fn parses_sctp_address() {
        let ma = Multiaddr::from_parts(vec![Addr::Sctp(593)]);
        let parsed = Multiaddr::from_str("/sctp/593").unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.to_string(), "/sctp/593");
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
    fn parses_http_address() {
        let ma = Multiaddr::from_parts(vec![Addr::Http]);
        let parsed = Multiaddr::from_str("/http").unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.to_string(), "/http");
    }

    #[test]
    fn parses_https_address() {
        let ma = Multiaddr::from_parts(vec![Addr::Https]);
        let parsed = Multiaddr::from_str("/https").unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.to_string(), "/https");
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

    #[test]
    fn binary_read_write() {
        let ma = Multiaddr::from_str("/ip4/8.9.29.\
                                      40/udp/80/ipfs/QmSoLueR4xBeUbY9WZ9xGUUx\
                                      unbKWcrNFTDAadQJmocnWm")
                     .unwrap();
        let enc = ma.to_bytes().unwrap();
        let dec = Multiaddr::from_bytes(&enc[..]).unwrap();
        assert_eq!(dec, ma);
    }
}
