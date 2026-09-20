//! Upstream resolution: the daemon's own answers for allowed names.

use std::net::{IpAddr, Ipv4Addr};

/// Addresses the daemon knows for `hostname` without asking anyone.
///
/// An empty result means "no records here": the front-ends then hand the
/// name to the next resolver in line.
pub async fn upstream_resolve(hostname: &str) -> Vec<IpAddr> {
    // TODO: replace with hickory-dns, trust-dns, or a real backend.
    match hostname {
        "example.local" => vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        _ => vec![],
    }
}
