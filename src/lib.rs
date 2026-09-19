//! NSS module — `libnss_deezns.so.2`
//!
//! nsswitch.conf:
//!     hosts: files deezns [!UNAVAIL=return] dns
//!
//! The `[!UNAVAIL=return]` action is important: it tells glibc that if
//! deezns returns UNAVAIL (our "pass through" signal), it should NOT stop
//! the chain — it should continue to `dns`.  Without it, glibc's default
//! for UNAVAIL is to stop looking.
//!
//! Verdict mapping:
//!   Denied      → Response::NotFound   (authoritative NXDOMAIN — stops chain)
//!   PassThrough → Response::Unavail    (we have no opinion — try next source)
//!   Resolved    → Response::Success    (here are the addresses)

mod protocol;

use protocol::{ResolveRequest, ResolveResponse, SOCKET_PATH};

use libnss::host::{AddressFamily, Addresses, Host, HostHooks};
use libnss::interop::Response;

use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;

// ---------------------------------------------------------------------------
// Wire helper (blocking — we're inside a synchronous glibc callback)
// ---------------------------------------------------------------------------

fn query_daemon(hostname: &str) -> Option<ResolveResponse> {
    let mut stream = UnixStream::connect(SOCKET_PATH).ok()?;

    let req = ResolveRequest {
        hostname: hostname.to_string(),
    };
    let mut buf = serde_json::to_vec(&req).ok()?;
    buf.push(b'\n');
    stream.write_all(&buf).ok()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;

    serde_json::from_str(&line).ok()
}

// ---------------------------------------------------------------------------
// Address family filtering helper
// ---------------------------------------------------------------------------

fn filter_addrs(addrs: Vec<IpAddr>, family: AddressFamily) -> Option<Addresses> {
    match family {
        AddressFamily::IPv4 => {
            let v4: Vec<_> = addrs
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(a) => Some(a),
                    _ => None,
                })
                .collect();
            if v4.is_empty() {
                None
            } else {
                Some(Addresses::V4(v4))
            }
        }
        AddressFamily::IPv6 => {
            let v6: Vec<_> = addrs
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(a) => Some(a),
                    _ => None,
                })
                .collect();
            if v6.is_empty() {
                None
            } else {
                Some(Addresses::V6(v6))
            }
        }
        _ => {
            // AF_UNSPEC — return whatever we have, prefer v4.
            let (v4, v6): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv4());
            if !v4.is_empty() {
                Some(Addresses::V4(
                    v4.into_iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V4(a) => Some(a),
                            _ => None,
                        })
                        .collect(),
                ))
            } else if !v6.is_empty() {
                Some(Addresses::V6(
                    v6.into_iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V6(a) => Some(a),
                            _ => None,
                        })
                        .collect(),
                ))
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NSS glue
// ---------------------------------------------------------------------------

struct DeeznsHost;
libnss::libnss_host_hooks!(deezns, DeeznsHost);

impl HostHooks for DeeznsHost {
    fn get_all_entries() -> Response<Vec<Host>> {
        Response::NotFound
    }

    fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host> {
        let resp = match query_daemon(name) {
            Some(r) => r,
            // Can't reach daemon — tell glibc we're unavailable so it
            // falls through to the next nsswitch source.
            None => return Response::Unavail,
        };

        match resp {
            // ── NXDOMAIN: authoritatively denied ─────────────────────
            // Response::NotFound tells glibc "this name does not exist"
            // and (with default nsswitch actions) stops the chain.
            ResolveResponse::Denied { .. } => Response::NotFound,

            // ── Pass through: we have no opinion ─────────────────────
            // Response::Unavail + the `[!UNAVAIL=return]` nsswitch
            // action causes glibc to try the next source.
            ResolveResponse::PassThrough => Response::Unavail,

            // ── Resolved ─────────────────────────────────────────────
            ResolveResponse::Resolved { addresses } => match filter_addrs(addresses, family) {
                Some(addrs) => Response::Success(Host {
                    name: name.to_string(),
                    addresses: addrs,
                    aliases: vec![],
                }),
                None => Response::NotFound,
            },
        }
    }

    fn get_host_by_addr(_addr: IpAddr) -> Response<Host> {
        Response::NotFound
    }
}
