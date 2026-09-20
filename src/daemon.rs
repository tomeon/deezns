//! deezns-daemon — async DNS resolver daemon with CEL-based policy.

mod blocklist;
mod nscd;
mod peercred;
mod policy;
mod protocol;
mod upstream;

use peercred::peer_caller;
use policy::{PolicyConfig, PolicyEngine, PolicyVerdict};
use protocol::{ResolveRequest, ResolveResponse, SOCKET_PATH};
use upstream::upstream_resolve;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use tracing::{error, info};

// ---------------------------------------------------------------------------
// Policy socket: one JSON request per line, identified by SO_PEERCRED
// ---------------------------------------------------------------------------

async fn handle_connection(stream: UnixStream, engine: Arc<PolicyEngine>) -> io::Result<()> {
    let caller = peer_caller(&stream)?;
    info!(?caller, "accepted connection");

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

        let verdict = engine.evaluate_for(&req.hostname, &caller);

        let resp = match verdict {
            PolicyVerdict::Denied(reason) => {
                info!(
                    hostname = req.hostname,
                    peer.uid = caller.uid,
                    peer.pid = caller.pid_value(),
                    %reason,
                    "DENIED"
                );
                ResolveResponse::Denied { reason }
            }

            PolicyVerdict::PassThrough => {
                info!(
                    hostname = req.hostname,
                    peer.uid = caller.uid,
                    peer.pid = caller.pid_value(),
                    "PASSTHROUGH"
                );
                ResolveResponse::PassThrough
            }

            PolicyVerdict::Allowed => {
                let addrs = upstream_resolve(&req.hostname).await;
                if addrs.is_empty() {
                    info!(
                        hostname = req.hostname,
                        peer.uid = caller.uid,
                        peer.pid = caller.pid_value(),
                        "ALLOWED (no local records, passing through)"
                    );
                    ResolveResponse::PassThrough
                } else {
                    info!(
                        hostname = req.hostname,
                        peer.uid = caller.uid,
                        peer.pid = caller.pid_value(),
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

fn bind_policy_socket() -> io::Result<UnixListener> {
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
    Ok(listener)
}

async fn serve_policy_socket(listener: UnixListener, engine: Arc<PolicyEngine>) -> io::Result<()> {
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

    let invalid = |e: Box<dyn std::error::Error>| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to load policy from {}: {e}", config_path.display()),
        )
    };
    let config = PolicyConfig::from_path(&config_path).map_err(invalid)?;
    let engine = Arc::new(PolicyEngine::from_config(&config).map_err(invalid)?);

    // Bind everything before serving anything, so a bad configuration fails
    // the whole daemon instead of half of it.
    let policy_listener = bind_policy_socket()?;
    let nscd_front = match &config.nscd_frontend {
        Some(front_cfg) => {
            let front = Arc::new(nscd::Frontend::new(front_cfg, Arc::clone(&engine)));
            let listener = front.bind()?;
            info!(
                path = %front.listen_path().display(),
                upstream = %front_cfg.upstream.display(),
                "listening (nscd front-end)"
            );
            Some((front, listener))
        }
        None => None,
    };

    let mut tasks = JoinSet::new();
    tasks.spawn(serve_policy_socket(policy_listener, engine));
    if let Some((front, listener)) = nscd_front {
        tasks.spawn(front.serve(listener));
    }

    // The listeners run forever; the first one to stop takes the daemon
    // down with its error.
    match tasks.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(e)) => Err(io::Error::other(format!("listener task failed: {e}"))),
        None => Ok(()),
    }
}
