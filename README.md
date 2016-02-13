# rs-multiaddr

A [multiaddr](https://github.com/jbenet/multiaddr) library for Rust. Tested against stable and beta rust, but should work with nightlies as well.

```rust
extern crate multiaddr;
use multiaddr::*;

fn main() {
	let addr = "/ip4/127.0.0.1/tcp/80".parse::<Multiaddr>().unwrap();

	assert!(!addr.contains_ipv6());
	assert!(addr.contains_ipv4());

	assert!(addr.parts()[0].is_ipv4());
	assert!(addr.parts()[1].is_tcp());

	assert_eq!(addr.parts()[1].to_string(), "/tcp/80");
	assert_eq!(addr.to_string(), "/ip4/127.0.0.1/tcp/80");

	let proxy = "/ip6/2001::1/udp/5938".parse::<Multiaddr>().unwrap();
	let proxied = proxy.encapsulate(&addr);

	assert_eq!(proxied.parts().len(), 4);
	assert_eq!(proxied.to_string(), "/ip6/2001::1/udp/5938/ip4/127.0.0.1/tcp/80");
}
```