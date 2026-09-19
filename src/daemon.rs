//! deezns-daemon — async DNS resolver daemon with CEL-based policy.

mod blocklist;
mod policy;
mod protocol;

use policy::{PolicyEngine, PolicyVerdict};
use protocol::{ResolveRequest, ResolveResponse, SOCKET_PATH};

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info};

// ---------------------------------------------------------------------------
// SO_PEERCRED
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PeerCred {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

fn get_peer_cred(stream: &UnixStream) -> io::Result<PeerCred> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(PeerCred {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

// ---------------------------------------------------------------------------
// Upstream resolution stub
// ---------------------------------------------------------------------------

async fn upstream_resolve(hostname: &str) -> Vec<IpAddr> {
    // TODO: replace with hickory-dns, trust-dns, or a real backend.
    match hostname {
        "example.local" => vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(stream: UnixStream, engine: Arc<PolicyEngine>) -> io::Result<()> {
    let peer = get_peer_cred(&stream)?;
    info!(?peer, "accepted connection");

    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let req: ResolveRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                error!(%e, "bad request");
                continue;
            }
        };

        let verdict = engine.evaluate(&req.hostname, peer.uid, peer.gid, peer.pid);

        let resp = match verdict {
            PolicyVerdict::Denied(reason) => {
                info!(
                    hostname = req.hostname,
                    peer.uid, peer.pid, %reason,
                    "DENIED"
                );
                ResolveResponse::Denied { reason }
            }

            PolicyVerdict::PassThrough => {
                info!(hostname = req.hostname, peer.uid, peer.pid, "PASSTHROUGH");
                ResolveResponse::PassThrough
            }

            PolicyVerdict::Allowed => {
                let addrs = upstream_resolve(&req.hostname).await;
                if addrs.is_empty() {
                    info!(
                        hostname = req.hostname,
                        peer.uid, peer.pid, "ALLOWED (no local records, passing through)"
                    );
                    ResolveResponse::PassThrough
                } else {
                    info!(
                        hostname = req.hostname,
                        peer.uid,
                        peer.pid,
                        count = addrs.len(),
                        "RESOLVED"
                    );
                    ResolveResponse::Resolved { addresses: addrs }
                }
            }
        };

        let mut buf = serde_json::to_vec(&resp)?;
        buf.push(b'\n');
        writer.write_all(&buf).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

const DEFAULT_CONFIG_PATH: &str = "/etc/deezns/policy.toml";

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = std::env::var("DEEZNS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH));

    let engine = PolicyEngine::load(&config_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to load policy from {}: {e}", config_path.display()),
        )
    })?;
    let engine = Arc::new(engine);

    let path = Path::new(SOCKET_PATH);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(path)?;
    info!(path = SOCKET_PATH, "listening");

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;

    loop {
        let (stream, _addr) = listener.accept().await?;
        let eng = Arc::clone(&engine);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, eng).await {
                error!(%e, "connection handler failed");
            }
        });
    }
}
