//! DNS front-end.
//!
//! The daemon answers DNS itself on a loopback address, so that the policy
//! applies to every resolver on the machine, glibc's `dns` source and
//! programs with their own DNS client alike.  A query carries no
//! credentials, so the caller is identified from the socket it came out of
//! (see `identify.rs`): the uid is always available, the gid and pid only
//! when the daemon may read other processes' file descriptors.
//!
//! Denied names get NXDOMAIN, the daemon's own records are answered
//! directly, and everything else is forwarded verbatim to the configured
//! upstream server over the same transport the client used; an upstream
//! that does not answer yields SERVFAIL.  Only the question section is
//! interpreted, so any record type and EDNS pass through untouched.

use crate::identify::{identify, Transport};
use crate::policy::{Caller, DnsFrontendConfig, PolicyEngine, PolicyVerdict};
use crate::upstream::upstream_resolve;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u16 = 0;
pub const RCODE_FORMERR: u16 = 1;
pub const RCODE_SERVFAIL: u16 = 2;
pub const RCODE_NXDOMAIN: u16 = 3;

const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE: u16 = 0x7800;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;

const HEADER_LEN: usize = 12;
/// Largest DNS message over UDP we accept; EDNS clients advertise up to
/// 4096 and the TCP length prefix allows 65535.
const MAX_MESSAGE: usize = 65535;
/// TTL of the daemon's own answers.
const ANSWER_TTL: u32 = 60;

/// The one question of a query, and where it ends in the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Lower-cased, without the trailing dot; empty for the root.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    pub flags: u16,
    pub question: Question,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    NotAQuery,
    QuestionCount(u16),
    BadName,
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

impl Query {
    /// Parse a query with exactly one question; anything else is refused,
    /// since a message we cannot judge must not be forwarded unjudged.
    pub fn parse(raw: &[u8]) -> Result<Query, ParseError> {
        if raw.len() < HEADER_LEN {
            return Err(ParseError::TooShort);
        }
        let id = be16(raw, 0).unwrap();
        let flags = be16(raw, 2).unwrap();
        if flags & FLAG_QR != 0 {
            return Err(ParseError::NotAQuery);
        }
        let qdcount = be16(raw, 4).unwrap();
        if qdcount != 1 {
            return Err(ParseError::QuestionCount(qdcount));
        }

        let mut labels = Vec::new();
        let mut at = HEADER_LEN;
        loop {
            let len = *raw.get(at).ok_or(ParseError::BadName)? as usize;
            at += 1;
            if len == 0 {
                break;
            }
            // Compression pointers have no business in a question.
            if len > 63 {
                return Err(ParseError::BadName);
            }
            let label = raw.get(at..at + len).ok_or(ParseError::BadName)?;
            labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
            at += len;
            if at - HEADER_LEN > 255 {
                return Err(ParseError::BadName);
            }
        }
        let qtype = be16(raw, at).ok_or(ParseError::TooShort)?;
        let qclass = be16(raw, at + 2).ok_or(ParseError::TooShort)?;
        Ok(Query {
            id,
            flags,
            question: Question {
                name: labels.join("."),
                qtype,
                qclass,
                end: at + 4,
            },
            raw: raw.to_vec(),
        })
    }

    /// The question section as it appeared in the query.
    fn question_bytes(&self) -> &[u8] {
        &self.raw[HEADER_LEN..self.question.end]
    }

    /// A response header for this query with the question echoed back:
    /// QR set, opcode and RD copied, RA set, no authority or additional
    /// records.
    fn response(&self, rcode: u16, answers: &[u8], ancount: u16) -> Vec<u8> {
        let flags = FLAG_QR | (self.flags & FLAG_OPCODE) | (self.flags & FLAG_RD) | FLAG_RA | rcode;
        let mut out = Vec::with_capacity(self.question.end + answers.len());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ancount.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(self.question_bytes());
        out.extend_from_slice(answers);
        out
    }

    pub fn nxdomain(&self) -> Vec<u8> {
        self.response(RCODE_NXDOMAIN, &[], 0)
    }

    pub fn servfail(&self) -> Vec<u8> {
        self.response(RCODE_SERVFAIL, &[], 0)
    }

    /// NOERROR with the addresses matching the question type as answers
    /// (none, for other types: a NODATA answer).
    pub fn answer(&self, addrs: &[IpAddr]) -> Vec<u8> {
        let mut answers = Vec::new();
        let mut count = 0u16;
        for addr in addrs {
            let rdata: Vec<u8> = match (addr, self.question.qtype) {
                (IpAddr::V4(a), TYPE_A) => a.octets().to_vec(),
                (IpAddr::V6(a), TYPE_AAAA) => a.octets().to_vec(),
                _ => continue,
            };
            // Name: a pointer to the question's name at offset 12.
            answers.extend_from_slice(&[0xC0, HEADER_LEN as u8]);
            answers.extend_from_slice(&self.question.qtype.to_be_bytes());
            answers.extend_from_slice(&CLASS_IN.to_be_bytes());
            answers.extend_from_slice(&ANSWER_TTL.to_be_bytes());
            answers.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            answers.extend_from_slice(&rdata);
            count += 1;
        }
        self.response(RCODE_NOERROR, &answers, count)
    }
}

/// FORMERR for a message we could not parse: the id is echoed when there
/// is one, so the client can match the failure to its query.
pub fn formerr(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![0; HEADER_LEN];
    if raw.len() >= 2 {
        out[..2].copy_from_slice(&raw[..2]);
    }
    out[2..4].copy_from_slice(&(FLAG_QR | RCODE_FORMERR).to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// The front-end
// ---------------------------------------------------------------------------

pub struct Frontend {
    listen: SocketAddr,
    upstream: SocketAddr,
    timeout: Duration,
    engine: Arc<PolicyEngine>,
}

impl Frontend {
    pub fn new(config: &DnsFrontendConfig, engine: Arc<PolicyEngine>) -> Self {
        Frontend {
            listen: config.listen,
            upstream: config.upstream,
            timeout: Duration::from_millis(config.upstream_timeout_ms),
            engine,
        }
    }

    pub async fn bind(&self) -> io::Result<(UdpSocket, TcpListener)> {
        Ok((
            UdpSocket::bind(self.listen).await?,
            TcpListener::bind(self.listen).await?,
        ))
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen
    }

    pub async fn serve(self: Arc<Self>, udp: UdpSocket, tcp: TcpListener) -> io::Result<()> {
        tokio::try_join!(Arc::clone(&self).serve_udp(udp), self.serve_tcp(tcp))?;
        Ok(())
    }

    async fn serve_udp(self: Arc<Self>, socket: UdpSocket) -> io::Result<()> {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; MAX_MESSAGE];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await?;
            let message = buf[..n].to_vec();
            let front = Arc::clone(&self);
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                let reply = front.respond(&message, peer, Transport::Udp).await;
                if let Err(e) = socket.send_to(&reply, peer).await {
                    debug!(%e, %peer, "cannot send DNS reply");
                }
            });
        }
    }

    async fn serve_tcp(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            let front = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = front.serve_tcp_connection(stream, peer).await {
                    debug!(%e, %peer, "DNS TCP connection ended with error");
                }
            });
        }
    }

    /// Length-prefixed messages, as many as the client sends.
    async fn serve_tcp_connection(
        &self,
        mut stream: TcpStream,
        peer: SocketAddr,
    ) -> io::Result<()> {
        loop {
            let mut len = [0u8; 2];
            match stream.read_exact(&mut len).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
            let mut message = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut message).await?;
            let reply = self.respond(&message, peer, Transport::Tcp).await;
            stream
                .write_all(&(reply.len() as u16).to_be_bytes())
                .await?;
            stream.write_all(&reply).await?;
        }
    }

    /// The reply to one message from `peer`.
    pub async fn respond(&self, raw: &[u8], peer: SocketAddr, transport: Transport) -> Vec<u8> {
        let query = match Query::parse(raw) {
            Ok(q) => q,
            Err(e) => {
                warn!(?e, %peer, "unparseable DNS message");
                return formerr(raw);
            }
        };
        // Root queries carry no name to judge.
        if query.question.name.is_empty() {
            return self.forward(&query, transport).await;
        }

        // Reading /proc is blocking work.
        let caller = tokio::task::spawn_blocking(move || identify(transport, peer))
            .await
            .unwrap_or_else(|_| Caller::unknown());
        let hostname = query.question.name.as_str();

        match self.engine.evaluate_for(hostname, &caller) {
            PolicyVerdict::Denied(reason) => {
                info!(
                    hostname,
                    qtype = query.question.qtype,
                    peer.uid = caller.uid_value(),
                    peer.gid = caller.gid_value(),
                    peer.pid = caller.pid_value(),
                    %reason,
                    "DENIED"
                );
                query.nxdomain()
            }
            PolicyVerdict::PassThrough => {
                info!(
                    hostname,
                    qtype = query.question.qtype,
                    peer.uid = caller.uid_value(),
                    peer.gid = caller.gid_value(),
                    peer.pid = caller.pid_value(),
                    "PASSTHROUGH"
                );
                self.forward(&query, transport).await
            }
            PolicyVerdict::Allowed => {
                let addrs = upstream_resolve(hostname).await;
                if addrs.is_empty() {
                    info!(
                        hostname,
                        qtype = query.question.qtype,
                        peer.uid = caller.uid_value(),
                        peer.gid = caller.gid_value(),
                        peer.pid = caller.pid_value(),
                        "ALLOWED (no local records, forwarding upstream)"
                    );
                    self.forward(&query, transport).await
                } else {
                    info!(
                        hostname,
                        qtype = query.question.qtype,
                        peer.uid = caller.uid_value(),
                        peer.gid = caller.gid_value(),
                        peer.pid = caller.pid_value(),
                        count = addrs.len(),
                        "RESOLVED"
                    );
                    query.answer(&addrs)
                }
            }
        }
    }

    /// Relay the query to the upstream server over the client's transport.
    async fn forward(&self, query: &Query, transport: Transport) -> Vec<u8> {
        let relayed = tokio::time::timeout(self.timeout, async {
            match transport {
                Transport::Udp => self.forward_udp(&query.raw).await,
                Transport::Tcp => self.forward_tcp(&query.raw).await,
            }
        })
        .await;
        match relayed {
            Ok(Ok(reply)) => reply,
            Ok(Err(e)) => {
                warn!(%e, upstream = %self.upstream, "upstream DNS failed, answering SERVFAIL");
                query.servfail()
            }
            Err(_) => {
                warn!(upstream = %self.upstream, "upstream DNS timed out, answering SERVFAIL");
                query.servfail()
            }
        }
    }

    async fn forward_udp(&self, raw: &[u8]) -> io::Result<Vec<u8>> {
        let local: SocketAddr = if self.upstream.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(self.upstream).await?;
        socket.send(raw).await?;
        let mut buf = vec![0u8; MAX_MESSAGE];
        loop {
            let n = socket.recv(&mut buf).await?;
            // Only the answer to our question, not a stray datagram.
            if n >= 2 && buf[..2] == raw[..2] {
                return Ok(buf[..n].to_vec());
            }
        }
    }

    async fn forward_tcp(&self, raw: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect(self.upstream).await?;
        stream.write_all(&(raw.len() as u16).to_be_bytes()).await?;
        stream.write_all(raw).await?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut reply).await?;
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

    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    /// A query the way a stub resolver builds it: RD set, one question.
    pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&FLAG_RD.to_be_bytes());
        q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.').filter(|l| !l.is_empty()) {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn rcode(reply: &[u8]) -> u16 {
        be16(reply, 2).unwrap() & 0x000F
    }

    fn ancount(reply: &[u8]) -> u16 {
        be16(reply, 6).unwrap()
    }

    #[test]
    fn queries_parse() {
        let raw = build_query(0x1234, "Sub.Example.TEST", TYPE_AAAA);
        let query = Query::parse(&raw).unwrap();
        assert_eq!(query.id, 0x1234);
        assert_eq!(query.question.name, "sub.example.test");
        assert_eq!(query.question.qtype, TYPE_AAAA);
        assert_eq!(query.question.qclass, CLASS_IN);
        assert_eq!(query.question.end, raw.len());

        let root = Query::parse(&build_query(1, ".", TYPE_A)).unwrap();
        assert_eq!(root.question.name, "");

        assert_eq!(Query::parse(&raw[..11]), Err(ParseError::TooShort));

        let mut response = raw.clone();
        response[2] |= 0x80;
        assert_eq!(Query::parse(&response), Err(ParseError::NotAQuery));

        let mut two_questions = raw.clone();
        two_questions[5] = 2;
        assert_eq!(
            Query::parse(&two_questions),
            Err(ParseError::QuestionCount(2))
        );

        let mut pointer = raw.clone();
        pointer[12] = 0xC0;
        assert_eq!(Query::parse(&pointer), Err(ParseError::BadName));

        let truncated = &raw[..raw.len() - 1];
        assert_eq!(Query::parse(truncated), Err(ParseError::TooShort));
    }

    #[test]
    fn negative_replies_echo_the_question() {
        let raw = build_query(7, "blocked.test", TYPE_A);
        let query = Query::parse(&raw).unwrap();

        let reply = query.nxdomain();
        assert_eq!(be16(&reply, 0), Some(7));
        assert_eq!(
            be16(&reply, 2),
            Some(FLAG_QR | FLAG_RD | FLAG_RA | RCODE_NXDOMAIN)
        );
        assert_eq!(&reply[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&reply[12..], &raw[12..]);

        assert_eq!(rcode(&query.servfail()), RCODE_SERVFAIL);

        let junk = formerr(&[0xAB, 0xCD, 1, 2]);
        assert_eq!(be16(&junk, 0), Some(0xABCD));
        assert_eq!(rcode(&junk), RCODE_FORMERR);
        assert_eq!(junk.len(), HEADER_LEN);
        assert_eq!(formerr(&[]).len(), HEADER_LEN);
    }

    #[test]
    fn answers_carry_the_addresses_of_the_asked_type() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6 = IpAddr::V6("fd00::1".parse().unwrap());

        let raw = build_query(9, "example.local", TYPE_A);
        let query = Query::parse(&raw).unwrap();
        let reply = query.answer(&[v4, v6]);
        assert_eq!(rcode(&reply), RCODE_NOERROR);
        assert_eq!(ancount(&reply), 1);
        let rr = &reply[raw.len()..];
        let mut expected = vec![0xC0, 12, 0, 1, 0, 1];
        expected.extend_from_slice(&ANSWER_TTL.to_be_bytes());
        expected.extend_from_slice(&[0, 4, 10, 0, 0, 1]);
        assert_eq!(rr, &expected[..]);

        let query = Query::parse(&build_query(9, "example.local", TYPE_AAAA)).unwrap();
        let reply = query.answer(&[v4, v6]);
        assert_eq!(ancount(&reply), 1);
        assert_eq!(
            &reply[reply.len() - 16..],
            &"fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets()
        );

        let query = Query::parse(&build_query(9, "example.local", 16)).unwrap();
        let reply = query.answer(&[v4, v6]);
        assert_eq!(rcode(&reply), RCODE_NOERROR);
        assert_eq!(ancount(&reply), 0);
    }

    // ── Integration: a front-end, a fake upstream and a client ────────────

    /// Answers every query with the query itself marked as a response and
    /// carrying one fixed A record; records what it saw.
    struct FakeUpstream {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    const CANNED_ADDRESS: [u8; 4] = [192, 0, 2, 99];

    fn canned_reply(query: &[u8]) -> Vec<u8> {
        let parsed = Query::parse(query).unwrap();
        parsed.answer(&[IpAddr::V4(Ipv4Addr::from(CANNED_ADDRESS))])
    }

    impl FakeUpstream {
        async fn start() -> Self {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = udp.local_addr().unwrap();
            let tcp = TcpListener::bind(addr).await.unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));

            let seen_udp = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_MESSAGE];
                loop {
                    let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
                    seen_udp.lock().unwrap().push(buf[..n].to_vec());
                    udp.send_to(&canned_reply(&buf[..n]), peer).await.unwrap();
                }
            });
            let seen_tcp = Arc::clone(&seen);
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = tcp.accept().await.unwrap();
                    let mut len = [0u8; 2];
                    stream.read_exact(&mut len).await.unwrap();
                    let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
                    stream.read_exact(&mut query).await.unwrap();
                    seen_tcp.lock().unwrap().push(query.clone());
                    let reply = canned_reply(&query);
                    stream
                        .write_all(&(reply.len() as u16).to_be_bytes())
                        .await
                        .unwrap();
                    stream.write_all(&reply).await.unwrap();
                }
            });
            FakeUpstream { addr, seen }
        }

        fn seen(&self) -> Vec<Vec<u8>> {
            self.seen.lock().unwrap().clone()
        }
    }

    async fn start_frontend(policy: &str, upstream: SocketAddr) -> Arc<Frontend> {
        let cfg: PolicyConfig = toml::from_str(policy).unwrap();
        let engine = Arc::new(PolicyEngine::from_config(&cfg).unwrap());
        let front = Arc::new(Frontend::new(
            &DnsFrontendConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream,
                upstream_timeout_ms: 300,
            },
            engine,
        ));
        let (udp, tcp) = front.bind().await.unwrap();
        // Both sockets bound to port 0 get different ports; the test uses
        // the UDP one and connects TCP to the TCP one.
        let udp_addr = udp.local_addr().unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        let front = Arc::new(Frontend {
            listen: udp_addr,
            upstream: front.upstream,
            timeout: front.timeout,
            engine: Arc::clone(&front.engine),
        });
        TCP_ADDR.with(|a| a.set(Some(tcp_addr)));
        tokio::spawn(Arc::clone(&front).serve(udp, tcp));
        front
    }

    thread_local! {
        static TCP_ADDR: std::cell::Cell<Option<SocketAddr>> = const { std::cell::Cell::new(None) };
    }

    async fn ask_udp(front: &Frontend, query: &[u8]) -> Vec<u8> {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(front.listen_addr()).await.unwrap();
        socket.send(query).await.unwrap();
        let mut buf = vec![0u8; MAX_MESSAGE];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .expect("reply within 5s")
            .unwrap();
        buf[..n].to_vec()
    }

    async fn ask_tcp(query: &[u8]) -> Vec<u8> {
        let addr = TCP_ADDR.with(|a| a.get()).unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(query).await.unwrap();
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    }

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
    async fn denied_names_get_nxdomain_without_asking_upstream() {
        let upstream = FakeUpstream::start().await;
        let front = start_frontend(&policy_for_this_user(), upstream.addr).await;

        let reply = ask_udp(&front, &build_query(1, "Blocked.Test", TYPE_A)).await;
        assert_eq!(rcode(&reply), RCODE_NXDOMAIN);
        assert_eq!(be16(&reply, 0), Some(1));

        let reply = ask_tcp(&build_query(2, "blocked.test", TYPE_AAAA)).await;
        assert_eq!(rcode(&reply), RCODE_NXDOMAIN);

        assert!(upstream.seen().is_empty());
    }

    #[tokio::test]
    async fn other_names_are_forwarded_over_the_clients_transport() {
        let upstream = FakeUpstream::start().await;
        let front = start_frontend(&policy_for_this_user(), upstream.addr).await;

        let udp_query = build_query(3, "unlisted.test", TYPE_A);
        let reply = ask_udp(&front, &udp_query).await;
        assert_eq!(reply, canned_reply(&udp_query));

        let tcp_query = build_query(4, "unlisted.test", 16);
        let reply = ask_tcp(&tcp_query).await;
        assert_eq!(reply, canned_reply(&tcp_query));

        assert_eq!(upstream.seen(), vec![udp_query, tcp_query]);
    }

    #[tokio::test]
    async fn the_caller_is_identified_from_its_socket() {
        let upstream = FakeUpstream::start().await;
        let front = start_frontend(&policy_for_this_user(), upstream.addr).await;

        // Our own socket: uid, gid and pid all match, so the name is allowed
        // and forwarded rather than denied by the following rule.
        let query = build_query(5, "mine.test", TYPE_A);
        let reply = ask_udp(&front, &query).await;
        assert_eq!(reply, canned_reply(&query));

        let query = build_query(6, "mine.test", TYPE_A);
        assert_eq!(ask_tcp(&query).await, canned_reply(&query));

        // A caller nobody can identify hits the deny rule.
        let parsed = Query::parse(&query).unwrap();
        let unknown_peer: SocketAddr = "192.0.2.77:1".parse().unwrap();
        let reply = front
            .respond(&parsed.raw, unknown_peer, Transport::Udp)
            .await;
        assert_eq!(rcode(&reply), RCODE_NXDOMAIN);
    }

    #[tokio::test]
    async fn the_daemons_own_records_are_answered_directly() {
        let upstream = FakeUpstream::start().await;
        let front = start_frontend(&policy_for_this_user(), upstream.addr).await;

        let query = build_query(8, "example.local", TYPE_A);
        let reply = ask_udp(&front, &query).await;
        assert_eq!(
            reply,
            Query::parse(&query)
                .unwrap()
                .answer(&[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))])
        );
        assert_eq!(ancount(&reply), 1);

        let reply = ask_udp(&front, &build_query(9, "example.local", TYPE_AAAA)).await;
        assert_eq!(rcode(&reply), RCODE_NOERROR);
        assert_eq!(ancount(&reply), 0);

        assert!(upstream.seen().is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_upstream_yields_servfail() {
        // Nothing listens here; UDP gets no answer (timeout), TCP is refused.
        let nowhere: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let front = start_frontend(&policy_for_this_user(), nowhere).await;

        let reply = ask_udp(&front, &build_query(10, "unlisted.test", TYPE_A)).await;
        assert_eq!(rcode(&reply), RCODE_SERVFAIL);
        let reply = ask_tcp(&build_query(11, "unlisted.test", TYPE_A)).await;
        assert_eq!(rcode(&reply), RCODE_SERVFAIL);

        // Denials never depend on the upstream.
        let reply = ask_udp(&front, &build_query(12, "blocked.test", TYPE_A)).await;
        assert_eq!(rcode(&reply), RCODE_NXDOMAIN);
    }

    #[tokio::test]
    async fn malformed_messages_get_formerr() {
        let upstream = FakeUpstream::start().await;
        let front = start_frontend(&policy_for_this_user(), upstream.addr).await;

        let reply = ask_udp(&front, &[0x12, 0x34, 0, 0]).await;
        assert_eq!(be16(&reply, 0), Some(0x1234));
        assert_eq!(rcode(&reply), RCODE_FORMERR);

        let mut two = build_query(13, "blocked.test", TYPE_A);
        two[5] = 2;
        assert_eq!(rcode(&ask_udp(&front, &two).await), RCODE_FORMERR);
        assert!(upstream.seen().is_empty());
    }
}
