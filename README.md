# rs-multiaddr

[![Build Status](https://travis-ci.org/micxjo/rs-multiaddr.svg?branch=master)](https://travis-ci.org/micxjo/rs-multiaddr)

A [multiaddr](https://github.com/jbenet/multiaddr) library for Rust. Tested against stable and beta rust, but should work with nightlies as well.

## Examples

The examples in this `README` are automatically tested using the awesome [Rust Skeptic](https://github.com/brson/rust-skeptic) tool.

```rust
extern crate multiaddr;
use multiaddr::*;

fn main() {
	let addr = "/ip4/127.0.0.1/http".parse::<Multiaddr>().unwrap();

	assert!(!addr.contains_ipv6());
	assert!(addr.contains_ipv4());

	assert!(addr.parts()[0].is_ipv4());
	assert!(addr.parts()[1].is_http());

	assert_eq!(addr.parts()[1].to_string(), "/http");
	assert_eq!(addr.to_string(), "/ip4/127.0.0.1/http");

	// Binary encoding
	let encoded: Vec<u8> = addr.to_bytes().unwrap();
	let decoded = Multiaddr::from_bytes(&encoded[..]).unwrap();
	assert_eq!(decoded, addr);

	// Encapsulation
	let proxy = "/ip6/2001::1/udp/5938".parse::<Multiaddr>().unwrap();
	let proxied = proxy.encapsulate(&addr);

	assert_eq!(proxied.parts().len(), 4);
	assert_eq!(proxied.to_string(), "/ip6/2001::1/udp/5938/ip4/127.0.0.1/http");
}
```