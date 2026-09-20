//! nscd-protocol front-end.
//!
//! On systems where every lookup goes through nscd's socket (NixOS runs
//! nsncd, and glibc consults `/var/run/nscd/socket` before doing anything
//! itself), an NSS module only ever meets nscd's credentials.  This
//! front-end takes nscd's place: it listens where glibc's client looks,
//! reads `SO_PEERCRED` of the process that actually asked, applies the
//! policy to host requests, and forwards everything else, byte for byte, to
//! the real nscd on another socket.
//!
//! The wire protocol is glibc's nscd protocol, version 2
//! (`nscd/nscd-client.h`): a 12-byte request header (version, type and key
//! length as native-endian `int32`) followed by the key, one request per
//! connection; the reply is a type-specific header followed by data, after
//! which the server closes the connection.
//!
//! Replying deserves care.  For host requests a reply with `found == -1`
//! tells glibc that the daemon does not serve the database, after which the
//! client does its next hundred lookups in-process, unfiltered; a closed
//! connection means the same.  A denial is therefore `found == 0` with
//! `error == HOST_NOT_FOUND`, and an unreachable upstream becomes
//! `found == 0` with `error == TRY_AGAIN`.  Non-host requests that cannot be
//! forwarded are answered by closing the connection on purpose: glibc then
//! serves that lookup from its built-in sources.

use crate::peercred::peer_caller;
use crate::policy::{Caller, NscdFrontendConfig, PolicyEngine, PolicyVerdict};
use crate::upstream::upstream_resolve;

use std::io;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

/// The only protocol version glibc has ever spoken.
pub const VERSION: i32 = 2;
/// Longest key nscd accepts (`MAXKEYLEN` in `nscd/nscd.h`).
pub const MAX_KEY_LEN: usize = 1024;
/// Size of `request_header`.
const HEADER_LEN: usize = 12;

// `h_errno` values (netdb.h).
pub const HOST_NOT_FOUND: i32 = 1;
pub const TRY_AGAIN: i32 = 2;
pub const NO_DATA: i32 = 4;

/// `request_type` from `nscd/nscd-client.h`, in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    GetPwByName,
    GetPwByUid,
    GetGrByName,
    GetGrByGid,
    GetHostByName,
    GetHostByNameV6,
    GetHostByAddr,
    GetHostByAddrV6,
    Shutdown,
    GetStat,
    Invalidate,
    GetFdPw,
    GetFdGr,
    GetFdHst,
    GetAi,
    InitGroups,
    GetServByName,
    GetServByPort,
    GetFdServ,
    GetNetGrEnt,
    InNetGr,
    GetFdNetGr,
}

impl RequestType {
    const ALL: [RequestType; 22] = [
        RequestType::GetPwByName,
        RequestType::GetPwByUid,
        RequestType::GetGrByName,
        RequestType::GetGrByGid,
        RequestType::GetHostByName,
        RequestType::GetHostByNameV6,
        RequestType::GetHostByAddr,
        RequestType::GetHostByAddrV6,
        RequestType::Shutdown,
        RequestType::GetStat,
        RequestType::Invalidate,
        RequestType::GetFdPw,
        RequestType::GetFdGr,
        RequestType::GetFdHst,
        RequestType::GetAi,
        RequestType::InitGroups,
        RequestType::GetServByName,
        RequestType::GetServByPort,
        RequestType::GetFdServ,
        RequestType::GetNetGrEnt,
        RequestType::InNetGr,
        RequestType::GetFdNetGr,
    ];

    pub fn from_i32(value: i32) -> Option<Self> {
        usize::try_from(value)
            .ok()
            .and_then(|i| Self::ALL.get(i).copied())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn as_i32(self) -> i32 {
        Self::ALL.iter().position(|&t| t == self).unwrap() as i32
    }

    /// Requests whose key is a host name the policy applies to.  Reverse
    /// lookups carry an address, not a name, and are forwarded untouched.
    pub fn is_host_lookup(self) -> bool {
        matches!(
            self,
            RequestType::GetHostByName | RequestType::GetHostByNameV6 | RequestType::GetAi
        )
    }
}

/// One request as received: parsed enough to route it, and kept verbatim
/// so it can be forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub ty: RequestType,
    pub key: Vec<u8>,
    pub raw: Vec<u8>,
}

impl Request {
    /// Serialize a request the way glibc's client does.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn encode(ty: RequestType, key: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + key.len());
        bytes.extend_from_slice(&VERSION.to_ne_bytes());
        bytes.extend_from_slice(&ty.as_i32().to_ne_bytes());
        bytes.extend_from_slice(&(key.len() as i32).to_ne_bytes());
        bytes.extend_from_slice(key);
        bytes
    }

    /// Parse a complete request (header and key).
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_LEN {
            return Err(format!("request too short: {} bytes", bytes.len()));
        }
        let int = |at: usize| i32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap());
        let version = int(0);
        if version != VERSION {
            return Err(format!("unsupported protocol version {version}"));
        }
        let ty = RequestType::from_i32(int(4))
            .ok_or_else(|| format!("unknown request type {}", int(4)))?;
        let key_len = usize::try_from(int(8)).map_err(|_| "negative key length".to_string())?;
        if key_len > MAX_KEY_LEN {
            return Err(format!("key length {key_len} exceeds {MAX_KEY_LEN}"));
        }
        if bytes.len() != HEADER_LEN + key_len {
            return Err(format!(
                "key length {key_len} does not match {} bytes of key",
                bytes.len() - HEADER_LEN
            ));
        }
        Ok(Request {
            ty,
            key: bytes[HEADER_LEN..].to_vec(),
            raw: bytes.to_vec(),
        })
    }

    /// The key as a host name: NUL-terminated UTF-8 (glibc sends the
    /// name including its terminator).
    pub fn hostname(&self) -> Option<&str> {
        let name = self.key.strip_suffix(b"\0").unwrap_or(&self.key);
        std::str::from_utf8(name).ok().filter(|s| !s.is_empty())
    }
}

async fn read_request(stream: &mut UnixStream) -> io::Result<Request> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let key_len = i32::from_ne_bytes(header[8..12].try_into().unwrap());
    let key_len = usize::try_from(key_len)
        .ok()
        .filter(|&n| n <= MAX_KEY_LEN)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad key length"))?;
    let mut raw = header.to_vec();
    raw.resize(HEADER_LEN + key_len, 0);
    stream.read_exact(&mut raw[HEADER_LEN..]).await?;
    Request::parse(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------
// Replies (nscd/nscd-client.h)
// ---------------------------------------------------------------------------

fn push_i32(buf: &mut Vec<u8>, value: i32) {
    buf.extend_from_slice(&value.to_ne_bytes());
}

fn address_bytes(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn address_family(addr: &IpAddr) -> i32 {
    match addr {
        IpAddr::V4(_) => libc::AF_INET,
        IpAddr::V6(_) => libc::AF_INET6,
    }
}

/// `ai_response_header` (24 bytes) followed by the packed addresses, one
/// family byte per address and the canonical name.
fn ai_reply(found: i32, error: i32, canon: &str, addrs: &[IpAddr]) -> Vec<u8> {
    let packed: Vec<u8> = addrs.iter().flat_map(address_bytes).collect();
    let families: Vec<u8> = addrs.iter().map(|a| address_family(a) as u8).collect();
    let canon_len = if found == 1 { canon.len() + 1 } else { 0 };

    let mut buf = Vec::new();
    push_i32(&mut buf, VERSION);
    push_i32(&mut buf, found);
    push_i32(&mut buf, addrs.len() as i32);
    push_i32(&mut buf, packed.len() as i32);
    push_i32(&mut buf, canon_len as i32);
    push_i32(&mut buf, error);
    if found == 1 {
        buf.extend_from_slice(&packed);
        buf.extend_from_slice(&families);
        buf.extend_from_slice(canon.as_bytes());
        buf.push(0);
    }
    buf
}

/// A negative `GETAI` reply that glibc reports to the caller as `error`
/// (an `h_errno` value) rather than falling back to an in-process lookup.
pub fn ai_not_found(error: i32) -> Vec<u8> {
    ai_reply(0, error, "", &[])
}

/// A `GETAI` reply carrying the daemon's own addresses for `canon`.
pub fn ai_found(canon: &str, addrs: &[IpAddr]) -> Vec<u8> {
    ai_reply(1, 0, canon, addrs)
}

/// `hst_response_header` (32 bytes) followed by the name and the address
/// list; the aliases count is always zero here.
fn hst_reply(found: i32, error: i32, name: &str, family: i32, addrs: &[IpAddr]) -> Vec<u8> {
    let length = if family == libc::AF_INET6 { 16 } else { 4 };
    let mut buf = Vec::new();
    push_i32(&mut buf, VERSION);
    push_i32(&mut buf, found);
    push_i32(&mut buf, if found == 1 { name.len() as i32 + 1 } else { 0 });
    push_i32(&mut buf, 0);
    push_i32(&mut buf, if found == 1 { family } else { -1 });
    push_i32(&mut buf, if found == 1 { length } else { -1 });
    push_i32(&mut buf, if found == 1 { addrs.len() as i32 } else { 0 });
    push_i32(&mut buf, error);
    if found == 1 {
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        for addr in addrs {
            buf.extend_from_slice(&address_bytes(addr));
        }
    }
    buf
}

/// A negative `GETHOSTBYNAME`/`GETHOSTBYNAMEv6` reply.
pub fn hst_not_found(error: i32) -> Vec<u8> {
    hst_reply(0, error, "", -1, &[])
}

/// A positive `GETHOSTBYNAME` (`AF_INET`) or `GETHOSTBYNAMEv6`
/// (`AF_INET6`) reply with the addresses of that family, or `None` when
/// there are none.
pub fn hst_found(name: &str, family: i32, addrs: &[IpAddr]) -> Option<Vec<u8>> {
    let matching: Vec<IpAddr> = addrs
        .iter()
        .copied()
        .filter(|a| address_family(a) == family)
        .collect();
    if matching.is_empty() {
        None
    } else {
        Some(hst_reply(1, 0, name, family, &matching))
    }
}

fn not_found(ty: RequestType, error: i32) -> Vec<u8> {
    match ty {
        RequestType::GetAi => ai_not_found(error),
        _ => hst_not_found(error),
    }
}

fn found(ty: RequestType, name: &str, addrs: &[IpAddr]) -> Vec<u8> {
    match ty {
        RequestType::GetAi => ai_found(name, addrs),
        RequestType::GetHostByName => {
            hst_found(name, libc::AF_INET, addrs).unwrap_or_else(|| hst_not_found(NO_DATA))
        }
        _ => hst_found(name, libc::AF_INET6, addrs).unwrap_or_else(|| hst_not_found(NO_DATA)),
    }
}

// ---------------------------------------------------------------------------
// The front-end
// ---------------------------------------------------------------------------

/// What to send back: bytes, or nothing before closing.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    Bytes(Vec<u8>),
    Close,
}

pub struct Frontend {
    listen: PathBuf,
    upstream: PathBuf,
    engine: Arc<PolicyEngine>,
}

impl Frontend {
    pub fn new(config: &NscdFrontendConfig, engine: Arc<PolicyEngine>) -> Self {
        Frontend {
            listen: config.listen.clone(),
            upstream: config.upstream.clone(),
            engine,
        }
    }

    pub fn listen_path(&self) -> &std::path::Path {
        &self.listen
    }

    /// Bind the listening socket, world-connectable like nscd's own.
    pub fn bind(&self) -> io::Result<UnixListener> {
        if self.listen.exists() {
            std::fs::remove_file(&self.listen)?;
        }
        if let Some(parent) = self.listen.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(&self.listen)?;
        std::fs::set_permissions(&self.listen, std::fs::Permissions::from_mode(0o666))?;
        Ok(listener)
    }

    pub async fn serve(self: Arc<Self>, listener: UnixListener) -> io::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let front = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = front.handle(stream).await {
                    debug!(%e, "nscd connection ended with error");
                }
            });
        }
    }

    async fn handle(&self, mut stream: UnixStream) -> io::Result<()> {
        let caller = peer_caller(&stream)?;
        let request = match read_request(&mut stream).await {
            Ok(r) => r,
            Err(e) => {
                warn!(%e, peer.uid = caller.uid, "bad nscd request");
                return Ok(());
            }
        };
        match self.reply_for(&request, &caller).await {
            Reply::Bytes(bytes) => stream.write_all(&bytes).await?,
            Reply::Close => {}
        }
        stream.shutdown().await
    }

    /// Decide what a request gets: an answer of our own, or the upstream's.
    pub async fn reply_for(&self, request: &Request, caller: &Caller) -> Reply {
        if !request.ty.is_host_lookup() {
            return match self.forward(request).await {
                Ok(bytes) => Reply::Bytes(bytes),
                Err(e) => {
                    warn!(%e, request = ?request.ty, "upstream nscd unreachable, closing");
                    Reply::Close
                }
            };
        }

        let Some(hostname) = request.hostname() else {
            warn!(request = ?request.ty, "host request without a name");
            return Reply::Close;
        };

        match self.engine.evaluate_for(hostname, caller) {
            PolicyVerdict::Denied(reason) => {
                info!(
                    hostname,
                    peer.uid = caller.uid,
                    peer.gid = caller.gid_value(),
                    peer.pid = caller.pid_value(),
                    %reason,
                    "DENIED"
                );
                Reply::Bytes(not_found(request.ty, HOST_NOT_FOUND))
            }
            PolicyVerdict::PassThrough => {
                info!(
                    hostname,
                    peer.uid = caller.uid,
                    peer.gid = caller.gid_value(),
                    peer.pid = caller.pid_value(),
                    "PASSTHROUGH"
                );
                self.forward_host(request).await
            }
            PolicyVerdict::Allowed => {
                let addrs = upstream_resolve(hostname).await;
                if addrs.is_empty() {
                    info!(
                        hostname,
                        peer.uid = caller.uid,
                        peer.gid = caller.gid_value(),
                        peer.pid = caller.pid_value(),
                        "ALLOWED (no local records, forwarding to nscd)"
                    );
                    self.forward_host(request).await
                } else {
                    info!(
                        hostname,
                        peer.uid = caller.uid,
                        peer.gid = caller.gid_value(),
                        peer.pid = caller.pid_value(),
                        count = addrs.len(),
                        "RESOLVED"
                    );
                    Reply::Bytes(found(request.ty, hostname, &addrs))
                }
            }
        }
    }

    async fn forward_host(&self, request: &Request) -> Reply {
        match self.forward(request).await {
            Ok(bytes) => Reply::Bytes(bytes),
            Err(e) => {
                error!(%e, "upstream nscd unreachable, answering TRY_AGAIN");
                Reply::Bytes(not_found(request.ty, TRY_AGAIN))
            }
        }
    }

    /// Send the request verbatim to the real nscd and collect its reply.
    async fn forward(&self, request: &Request) -> io::Result<Vec<u8>> {
        let mut upstream = UnixStream::connect(&self.upstream).await?;
        upstream.write_all(&request.raw).await?;
        let mut reply = Vec::new();
        upstream.read_to_end(&mut reply).await?;
        Ok(reply)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyConfig;

    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn ints(bytes: &[u8]) -> Vec<i32> {
        let (words, rest) = bytes.as_chunks::<4>();
        assert!(rest.is_empty(), "not a whole number of int32s");
        words.iter().map(|w| i32::from_ne_bytes(*w)).collect()
    }

    #[test]
    fn request_types_round_trip_in_declaration_order() {
        assert_eq!(RequestType::from_i32(0), Some(RequestType::GetPwByName));
        assert_eq!(RequestType::from_i32(4), Some(RequestType::GetHostByName));
        assert_eq!(RequestType::from_i32(14), Some(RequestType::GetAi));
        assert_eq!(RequestType::from_i32(21), Some(RequestType::GetFdNetGr));
        assert_eq!(RequestType::from_i32(22), None);
        assert_eq!(RequestType::from_i32(-1), None);
        for ty in RequestType::ALL {
            assert_eq!(RequestType::from_i32(ty.as_i32()), Some(ty));
        }
        assert!(RequestType::GetAi.is_host_lookup());
        assert!(RequestType::GetHostByNameV6.is_host_lookup());
        assert!(!RequestType::GetHostByAddr.is_host_lookup());
        assert!(!RequestType::GetPwByName.is_host_lookup());
    }

    #[test]
    fn requests_parse_and_encode() {
        let raw = Request::encode(RequestType::GetAi, b"Example.Test\0");
        assert_eq!(ints(&raw[..12]), vec![2, 14, 13]);
        let request = Request::parse(&raw).unwrap();
        assert_eq!(request.ty, RequestType::GetAi);
        assert_eq!(request.hostname(), Some("Example.Test"));
        assert_eq!(request.raw, raw);

        let mut bad_version = raw.clone();
        bad_version[..4].copy_from_slice(&1i32.to_ne_bytes());
        assert!(Request::parse(&bad_version)
            .unwrap_err()
            .contains("version"));

        let mut bad_type = raw.clone();
        bad_type[4..8].copy_from_slice(&99i32.to_ne_bytes());
        assert!(Request::parse(&bad_type).unwrap_err().contains("type"));

        let too_long = Request::encode(RequestType::GetAi, &vec![b'a'; MAX_KEY_LEN + 1]);
        assert!(Request::parse(&too_long).unwrap_err().contains("exceeds"));

        assert!(Request::parse(&raw[..11]).is_err());
        assert!(Request::parse(&raw[..raw.len() - 1]).is_err());

        let empty = Request::parse(&Request::encode(RequestType::GetAi, b"\0")).unwrap();
        assert_eq!(empty.hostname(), None);
    }

    #[test]
    fn getai_replies_follow_nscd_layout() {
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let reply = ai_found("a.test", &[v4, v6]);
        assert_eq!(ints(&reply[..24]), vec![2, 1, 2, 20, 7, 0]);
        let mut expected = vec![1, 2, 3, 4];
        expected.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        expected.extend_from_slice(&[libc::AF_INET as u8, libc::AF_INET6 as u8]);
        expected.extend_from_slice(b"a.test\0");
        assert_eq!(&reply[24..], &expected[..]);

        let denied = ai_not_found(HOST_NOT_FOUND);
        assert_eq!(ints(&denied), vec![2, 0, 0, 0, 0, HOST_NOT_FOUND]);
        assert_eq!(ints(&ai_not_found(TRY_AGAIN))[5], TRY_AGAIN);
    }

    #[test]
    fn gethostbyname_replies_follow_nscd_layout() {
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        let reply = hst_found("a.test", libc::AF_INET, &[v4, v6]).unwrap();
        assert_eq!(ints(&reply[..32]), vec![2, 1, 7, 0, libc::AF_INET, 4, 1, 0]);
        assert_eq!(&reply[32..], b"a.test\0\x01\x02\x03\x04");

        let reply = hst_found("a.test", libc::AF_INET6, &[v4, v6]).unwrap();
        assert_eq!(
            ints(&reply[..32]),
            vec![2, 1, 7, 0, libc::AF_INET6, 16, 1, 0]
        );
        assert_eq!(&reply[39..], &Ipv6Addr::LOCALHOST.octets()[..]);

        assert_eq!(hst_found("a.test", libc::AF_INET6, &[v4]), None);
        assert_eq!(
            ints(&hst_not_found(HOST_NOT_FOUND)),
            vec![2, 0, 0, 0, -1, -1, 0, HOST_NOT_FOUND]
        );
        assert_eq!(
            ints(&found(RequestType::GetHostByNameV6, "a.test", &[v4]))[7],
            NO_DATA
        );
    }

    // ── Integration: a front-end, a fake upstream and a client ────────────

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_socket(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("deezns-{}-{n}-{tag}.sock", std::process::id()))
    }

    /// Records every request it receives and answers each with `reply`.
    struct FakeUpstream {
        path: PathBuf,
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl FakeUpstream {
        async fn start(reply: &'static [u8]) -> Self {
            let path = temp_socket("upstream");
            let listener = UnixListener::bind(&path).unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let seen_by_server = Arc::clone(&seen);
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut buf = vec![0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    seen_by_server.lock().unwrap().push(buf[..n].to_vec());
                    stream.write_all(reply).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            FakeUpstream { path, seen }
        }

        fn seen(&self) -> Vec<Vec<u8>> {
            self.seen.lock().unwrap().clone()
        }
    }

    async fn start_frontend(policy: &str, upstream: &std::path::Path) -> Arc<Frontend> {
        let cfg: PolicyConfig = toml::from_str(policy).unwrap();
        let engine = Arc::new(PolicyEngine::from_config(&cfg).unwrap());
        let front = Arc::new(Frontend::new(
            &NscdFrontendConfig {
                listen: temp_socket("front"),
                upstream: upstream.to_path_buf(),
            },
            engine,
        ));
        let listener = front.bind().unwrap();
        tokio::spawn(Arc::clone(&front).serve(listener));
        front
    }

    /// Send one request and collect the reply; a connection the front-end
    /// closes (or resets, when it stops reading early) yields nothing.
    async fn ask(front: &Frontend, request: Vec<u8>) -> Vec<u8> {
        let mut stream = UnixStream::connect(front.listen_path()).await.unwrap();
        stream.write_all(&request).await.unwrap();
        let mut reply = Vec::new();
        if stream.read_to_end(&mut reply).await.is_err() {
            reply.clear();
        }
        reply
    }

    const CANNED: &[u8] = b"canned reply from upstream";

    fn policy_for_this_user() -> String {
        format!(
            r#"
            default_verdict = "passthrough"

            [[rules]]
            note = "blocked"
            expr = 'hostname == "blocked.test"'
            verdict = "deny"

            [[rules]]
            note = "mine"
            expr = 'uid == {uid} && gid == {gid} && pid == {pid} && hostname == "mine.test"'
            verdict = "allow"

            [[rules]]
            note = "not mine"
            expr = 'hostname == "mine.test"'
            verdict = "deny"

            [[rules]]
            note = "daemon record"
            expr = 'hostname == "example.local"'
            verdict = "allow"
            "#,
            uid = unsafe { libc::geteuid() },
            gid = unsafe { libc::getegid() },
            pid = std::process::id(),
        )
    }

    #[tokio::test]
    async fn denials_are_answered_without_asking_upstream() {
        let upstream = FakeUpstream::start(CANNED).await;
        let front = start_frontend(&policy_for_this_user(), &upstream.path).await;

        let reply = ask(
            &front,
            Request::encode(RequestType::GetAi, b"blocked.test\0"),
        )
        .await;
        assert_eq!(reply, ai_not_found(HOST_NOT_FOUND));

        let reply = ask(
            &front,
            Request::encode(RequestType::GetHostByName, b"BLOCKED.test\0"),
        )
        .await;
        assert_eq!(reply, hst_not_found(HOST_NOT_FOUND));

        assert!(upstream.seen().is_empty());
    }

    #[tokio::test]
    async fn passthrough_and_other_requests_are_forwarded_verbatim() {
        let upstream = FakeUpstream::start(CANNED).await;
        let front = start_frontend(&policy_for_this_user(), &upstream.path).await;

        let getai = Request::encode(RequestType::GetAi, b"unlisted.test\0");
        assert_eq!(ask(&front, getai.clone()).await, CANNED);

        let getpw = Request::encode(RequestType::GetPwByName, b"alice\0");
        assert_eq!(ask(&front, getpw.clone()).await, CANNED);

        let byaddr = Request::encode(RequestType::GetHostByAddr, &[127, 0, 0, 1]);
        assert_eq!(ask(&front, byaddr.clone()).await, CANNED);

        assert_eq!(upstream.seen(), vec![getai, getpw, byaddr]);
    }

    #[tokio::test]
    async fn the_callers_own_credentials_reach_the_policy() {
        let upstream = FakeUpstream::start(CANNED).await;
        let front = start_frontend(&policy_for_this_user(), &upstream.path).await;

        // We are the caller, so the uid/gid/pid rule matches and the name
        // is allowed (and, having no local records, forwarded).
        let reply = ask(&front, Request::encode(RequestType::GetAi, b"mine.test\0")).await;
        assert_eq!(reply, CANNED);

        // Directly: another caller gets the deny rule.
        let request = Request::parse(&Request::encode(RequestType::GetAi, b"mine.test\0")).unwrap();
        let someone_else = Caller::new(unsafe { libc::geteuid() } + 1, 0, 1);
        assert_eq!(
            front.reply_for(&request, &someone_else).await,
            Reply::Bytes(ai_not_found(HOST_NOT_FOUND))
        );
    }

    #[tokio::test]
    async fn the_daemons_own_records_are_answered_directly() {
        let upstream = FakeUpstream::start(CANNED).await;
        let front = start_frontend(&policy_for_this_user(), &upstream.path).await;
        let ten = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let reply = ask(
            &front,
            Request::encode(RequestType::GetAi, b"example.local\0"),
        )
        .await;
        assert_eq!(reply, ai_found("example.local", &[ten]));

        let reply = ask(
            &front,
            Request::encode(RequestType::GetHostByName, b"example.local\0"),
        )
        .await;
        assert_eq!(
            reply,
            hst_found("example.local", libc::AF_INET, &[ten]).unwrap()
        );

        let reply = ask(
            &front,
            Request::encode(RequestType::GetHostByNameV6, b"example.local\0"),
        )
        .await;
        assert_eq!(reply, hst_not_found(NO_DATA));

        assert!(upstream.seen().is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_upstream_degrades_safely() {
        let nowhere = temp_socket("nowhere");
        let front = start_frontend(&policy_for_this_user(), &nowhere).await;

        // Host lookups get a temporary failure, never a "no nscd" signal.
        let reply = ask(
            &front,
            Request::encode(RequestType::GetAi, b"unlisted.test\0"),
        )
        .await;
        assert_eq!(reply, ai_not_found(TRY_AGAIN));
        let reply = ask(
            &front,
            Request::encode(RequestType::GetHostByName, b"unlisted.test\0"),
        )
        .await;
        assert_eq!(reply, hst_not_found(TRY_AGAIN));

        // Denials still work without an upstream.
        let reply = ask(
            &front,
            Request::encode(RequestType::GetAi, b"blocked.test\0"),
        )
        .await;
        assert_eq!(reply, ai_not_found(HOST_NOT_FOUND));

        // Everything else: closed without a reply, so glibc serves it itself.
        let reply = ask(
            &front,
            Request::encode(RequestType::GetPwByName, b"alice\0"),
        )
        .await;
        assert!(reply.is_empty());
    }

    #[tokio::test]
    async fn malformed_requests_are_dropped() {
        let upstream = FakeUpstream::start(CANNED).await;
        let front = start_frontend(&policy_for_this_user(), &upstream.path).await;

        let mut bad_version = Request::encode(RequestType::GetAi, b"unlisted.test\0");
        bad_version[..4].copy_from_slice(&1i32.to_ne_bytes());
        assert!(ask(&front, bad_version).await.is_empty());

        let mut huge_key = Request::encode(RequestType::GetAi, b"x\0");
        huge_key[8..12].copy_from_slice(&(MAX_KEY_LEN as i32 + 1).to_ne_bytes());
        assert!(ask(&front, huge_key).await.is_empty());

        assert!(upstream.seen().is_empty());
    }
}
