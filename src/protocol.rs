use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Socket path — both daemon and NSS client agree on this.
///
/// Override at build time:
///   MYDNS_SOCKET_PATH=/my/custom.sock cargo build
///
/// The value is baked in by `build.rs` via `cargo:rustc-env`.
pub const SOCKET_PATH: &str = env!("MYDNS_SOCKET_PATH");

/// A DNS lookup request sent over the Unix socket.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResolveRequest {
    pub hostname: String,
}

/// The daemon's verdict for a lookup.
///
/// The three variants map onto distinct NSS behaviours:
///
/// - `Denied`      → the domain is on the denylist (or not on the allowlist)
///                   for this caller.  The NSS module returns an authoritative
///                   "not found" that **stops** the NSS chain (NXDOMAIN
///                   equivalent).
///
/// - `PassThrough` → the daemon has no opinion about this domain for this
///                   caller.  The NSS module signals glibc to move on to the
///                   next source in nsswitch.conf.
///
/// - `Resolved`    → the daemon resolved the name.  The NSS module returns
///                   the addresses.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "verdict")]
pub enum ResolveResponse {
    /// Authoritatively denied — NXDOMAIN.  Stops the NSS chain.
    Denied {
        /// Why the domain was denied (for logging / diagnostics).
        reason: String,
    },

    /// The daemon has no policy for this domain+caller combination.
    /// Punt to the next resolver in nsswitch.conf.
    PassThrough,

    /// Successfully resolved.
    Resolved {
        addresses: Vec<IpAddr>,
    },
}
