//! Who owns a local IP socket?
//!
//! A DNS query arriving over loopback carries no credentials, but the
//! kernel knows which socket it left from.  `/proc/net/{udp,udp6,tcp,tcp6}`
//! list every socket with its local and remote addresses, the uid of its
//! owner and its inode; the uid is readable by anyone.  Turning the inode
//! into a process (and from there into a gid) means finding it among
//! `/proc/<pid>/fd`.  Another user's fd directory is mode 0500 and owned by
//! that user, so listing it needs `CAP_DAC_READ_SEARCH`, and following its
//! links needs `CAP_SYS_PTRACE` (this is why `ss -p` wants root).  Without
//! both, the caller is identified by uid alone and `gid` and `pid` stay
//! unknown.
//!
//! Matching is done on the whole connection: the client's address and
//! port, and the server address the packet was sent to.  Both tables are
//! searched whatever the peer's family, since a dual-stack IPv6 socket
//! talking to an IPv4 listener shows up in the IPv6 table with an
//! IPv4-mapped address.  When several sockets fit equally well and belong
//! to different users, nobody is identified rather than someone at random.

use crate::policy::Caller;

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use procfs::process::{all_processes, FDTarget, Process};
use tracing::{debug, info, warn};

/// The transport a query arrived over, which decides the socket tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// A row of a socket table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub local: SocketAddr,
    /// `0.0.0.0:0` (or `[::]:0`) for an unconnected socket.
    pub remote: SocketAddr,
    pub uid: u32,
    pub inode: u64,
}

/// The outcome of looking a peer up in the socket tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketMatch {
    /// Exactly one socket fits best.
    One(SocketEntry),
    /// Several sockets of one user fit equally well: the uid is certain,
    /// the process is not.
    SameUser(u32),
    /// Sockets of different users fit equally well.
    Ambiguous,
    /// Nothing fits.
    None,
}

/// A table that cannot be read (no IPv6 on this kernel, say) is empty.
fn table<T>(name: &str, result: procfs::ProcResult<Vec<T>>) -> Vec<T> {
    result.unwrap_or_else(|e| {
        debug!(%e, table = name, "cannot read socket table");
        Vec::new()
    })
}

/// Both tables of a transport, whatever the peer's family.
fn socket_tables(transport: Transport) -> Vec<SocketEntry> {
    let mut entries = Vec::new();
    match transport {
        Transport::Udp => {
            let v4 = table("udp", procfs::net::udp());
            let v6 = table("udp6", procfs::net::udp6());
            for e in v4.into_iter().chain(v6) {
                entries.push(SocketEntry {
                    local: e.local_address,
                    remote: e.remote_address,
                    uid: e.uid,
                    inode: e.inode,
                });
            }
        }
        Transport::Tcp => {
            let v4 = table("tcp", procfs::net::tcp());
            let v6 = table("tcp6", procfs::net::tcp6());
            for e in v4.into_iter().chain(v6) {
                entries.push(SocketEntry {
                    local: e.local_address,
                    remote: e.remote_address,
                    uid: e.uid,
                    inode: e.inode,
                });
            }
        }
    }
    entries
}

/// IPv4-mapped IPv6 addresses compare equal to their IPv4 form.
fn same_host(a: IpAddr, b: IpAddr) -> bool {
    a.to_canonical() == b.to_canonical()
}

/// How well a row fits a packet from `peer` to `server`: `None` when it
/// cannot be the sender, otherwise higher is more specific.
fn fit(entry: &SocketEntry, peer: SocketAddr, server: SocketAddr) -> Option<u8> {
    if entry.local.port() != peer.port() {
        return None;
    }
    let local_exact = same_host(entry.local.ip(), peer.ip());
    if !local_exact && !entry.local.ip().is_unspecified() {
        return None;
    }

    let unconnected = entry.remote.port() == 0 && entry.remote.ip().is_unspecified();
    let remote_exact = entry.remote.port() == server.port()
        && (server.ip().is_unspecified() || same_host(entry.remote.ip(), server.ip()));
    if !unconnected && !remote_exact {
        return None;
    }

    Some(u8::from(remote_exact) * 2 + u8::from(local_exact))
}

/// The socket a packet from `peer` to `server` came out of.
pub fn find_socket(entries: &[SocketEntry], peer: SocketAddr, server: SocketAddr) -> SocketMatch {
    let mut best: Vec<&SocketEntry> = Vec::new();
    let mut best_fit = 0;
    for entry in entries {
        let Some(score) = fit(entry, peer, server) else {
            continue;
        };
        if best.is_empty() || score > best_fit {
            best = vec![entry];
            best_fit = score;
        } else if score == best_fit {
            best.push(entry);
        }
    }
    match best.as_slice() {
        [] => SocketMatch::None,
        [one] => SocketMatch::One((*one).clone()),
        [first, rest @ ..] => {
            if rest.iter().all(|e| e.uid == first.uid) {
                SocketMatch::SameUser(first.uid)
            } else {
                SocketMatch::Ambiguous
            }
        }
    }
}

/// Whether this process may read other processes' fd tables (it can
/// always read its own).  Probed once: pid 1 belongs to root, so listing
/// its fd directory and resolving an entry succeeds only with
/// `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE` (or as root).
fn can_inspect_other_processes() -> bool {
    static CAN: OnceLock<bool> = OnceLock::new();
    *CAN.get_or_init(|| {
        let can = Process::new(1)
            .and_then(|p| p.fd())
            .map(|mut fds| fds.next().is_some_and(|fd| fd.is_ok()))
            .unwrap_or(false);
        if !can {
            info!("cannot read other processes' file descriptors (needs CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE); DNS callers are identified by uid only");
        }
        can
    })
}

/// The process holding the socket with this inode, if it can be found.
pub fn process_with_socket(inode: u64) -> Option<Process> {
    // Our own process is always readable; anyone else's only with the
    // capabilities above.  Skip the (expensive) scan when it cannot succeed.
    let own = Process::myself().ok();
    let candidates: Box<dyn Iterator<Item = Process>> = if can_inspect_other_processes() {
        Box::new(all_processes().ok()?.filter_map(Result::ok))
    } else {
        Box::new(own.into_iter())
    };
    candidates.into_iter().find(|process| {
        process.fd().is_ok_and(|fds| {
            fds.filter_map(Result::ok)
                .any(|fd| matches!(fd.target, FDTarget::Socket(i) if i == inode))
        })
    })
}

/// Identify the process that sent from `peer` to `server` over
/// `transport`: uid from the socket tables, and gid and pid when the
/// owning process can be found.
pub fn identify(transport: Transport, peer: SocketAddr, server: SocketAddr) -> Caller {
    let entries = socket_tables(transport);
    match find_socket(&entries, peer, server) {
        SocketMatch::One(socket) => {
            let process = process_with_socket(socket.inode);
            let pid = process.as_ref().map(|p| p.pid());
            let gid = process.and_then(|p| p.status().ok()).map(|s| s.egid);
            Caller {
                uid: Some(socket.uid),
                gid,
                pid,
            }
        }
        SocketMatch::SameUser(uid) => Caller {
            uid: Some(uid),
            gid: None,
            pid: None,
        },
        SocketMatch::Ambiguous => {
            warn!(%peer, "several users' sockets match the peer address; caller unknown");
            Caller::unknown()
        }
        SocketMatch::None => {
            debug!(%peer, "no local socket matches the peer address");
            Caller::unknown()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn entry(local: &str, remote: &str, uid: u32, inode: u64) -> SocketEntry {
        SocketEntry {
            local: addr(local),
            remote: addr(remote),
            uid,
            inode,
        }
    }

    const SERVER: &str = "127.0.0.1:53";

    #[test]
    fn the_most_specific_matching_socket_wins() {
        let entries = [
            entry("0.0.0.0:5000", "0.0.0.0:0", 1000, 1),
            entry("127.0.0.1:5000", "0.0.0.0:0", 1001, 2),
            entry("127.0.0.1:5000", "127.0.0.1:53", 1002, 3),
            entry("127.0.0.1:5000", "127.0.0.1:54", 1003, 4),
        ];
        // Connected to us beats bound to our peer's address beats wildcard.
        assert_eq!(
            find_socket(&entries, addr("127.0.0.1:5000"), addr(SERVER)),
            SocketMatch::One(entries[2].clone())
        );
        assert_eq!(
            find_socket(&entries[..2], addr("127.0.0.1:5000"), addr(SERVER)),
            SocketMatch::One(entries[1].clone())
        );
        assert_eq!(
            find_socket(&entries[..1], addr("127.0.0.1:5000"), addr(SERVER)),
            SocketMatch::One(entries[0].clone())
        );
        // A socket connected elsewhere is never the sender.
        assert_eq!(
            find_socket(&entries[3..], addr("127.0.0.1:5000"), addr(SERVER)),
            SocketMatch::None
        );
        assert_eq!(
            find_socket(&entries, addr("127.0.0.1:5001"), addr(SERVER)),
            SocketMatch::None
        );
        assert_eq!(
            find_socket(&entries, addr("192.0.2.1:5000"), addr(SERVER)),
            SocketMatch::One(entries[0].clone())
        );
    }

    #[test]
    fn equally_good_sockets_of_different_users_identify_nobody() {
        let entries = [
            entry("127.0.0.1:5000", "127.0.0.1:53", 1000, 1),
            entry("127.0.0.1:5000", "127.0.0.1:53", 1001, 2),
        ];
        assert_eq!(
            find_socket(&entries, addr("127.0.0.1:5000"), addr(SERVER)),
            SocketMatch::Ambiguous
        );

        let same_user = [
            entry("127.0.0.1:5000", "127.0.0.1:53", 1000, 1),
            entry("127.0.0.1:5000", "127.0.0.1:53", 1000, 2),
        ];
        assert_eq!(
            find_socket(&same_user, addr("127.0.0.1:5000"), addr(SERVER)),
            SocketMatch::SameUser(1000)
        );
    }

    #[test]
    fn ipv4_mapped_rows_match_ipv4_peers() {
        let entries = [
            entry("[::ffff:127.0.0.1]:5000", "[::ffff:127.0.0.1]:53", 1000, 1),
            entry("[::]:5001", "[::]:0", 1001, 2),
        ];
        assert_eq!(
            find_socket(&entries, addr("127.0.0.1:5000"), addr(SERVER)),
            SocketMatch::One(entries[0].clone())
        );
        assert_eq!(
            find_socket(&entries, addr("127.0.0.1:5001"), addr(SERVER)),
            SocketMatch::One(entries[1].clone())
        );
        // And the other way round, for a listener on [::].
        assert_eq!(
            find_socket(&entries, addr("[::ffff:127.0.0.1]:5000"), addr("[::]:53")),
            SocketMatch::One(entries[0].clone())
        );
    }

    #[test]
    fn our_own_udp_socket_is_identified_fully() {
        // A connected UDP socket, as glibc's resolver makes: listed with its
        // local address and our address as the remote one.
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.connect((Ipv4Addr::LOCALHOST, 53)).unwrap();
        let local = socket.local_addr().unwrap();

        let caller = identify(Transport::Udp, local, addr(SERVER));
        assert_eq!(caller.uid, Some(unsafe { libc::geteuid() }));
        // Our own fd table is always readable, so the process is found.
        assert_eq!(caller.pid, Some(std::process::id() as i32));
        assert_eq!(caller.gid, Some(unsafe { libc::getegid() }));
    }

    /// Kernels without IPv6 (some sandboxes) cannot run the dual-stack
    /// cases; they are exercised in the NixOS VM test regardless.
    fn ipv6_available() -> bool {
        let available = UdpSocket::bind("[::1]:0").is_ok();
        if !available {
            eprintln!("skipping: no IPv6 on this kernel");
        }
        available
    }

    #[test]
    fn our_own_dual_stack_socket_is_identified_from_its_ipv4_peer_address() {
        if !ipv6_available() {
            return;
        }
        // An IPv6 socket talking to an IPv4 address: the IPv4 listener sees
        // an IPv4 peer, while the socket sits in the IPv6 table with an
        // IPv4-mapped address.
        let socket = UdpSocket::bind("[::]:0").unwrap();
        socket.connect("[::ffff:127.0.0.1]:53").unwrap();
        let mapped = socket.local_addr().unwrap();
        assert!(mapped.is_ipv6());
        let seen_by_listener = SocketAddr::new(mapped.ip().to_canonical(), mapped.port());
        assert!(seen_by_listener.is_ipv4());

        let caller = identify(Transport::Udp, seen_by_listener, addr(SERVER));
        assert_eq!(caller.uid, Some(unsafe { libc::geteuid() }));
        assert_eq!(caller.pid, Some(std::process::id() as i32));
    }

    #[test]
    fn our_own_tcp_sockets_are_identified_by_their_whole_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server = listener.local_addr().unwrap();
        let client = TcpStream::connect(server).unwrap();
        let local = client.local_addr().unwrap();

        let caller = identify(Transport::Tcp, local, server);
        assert_eq!(caller.uid, Some(unsafe { libc::geteuid() }));
        assert_eq!(caller.pid, Some(std::process::id() as i32));

        // The same client endpoint asked about from another server address
        // is not this connection.
        let other = SocketAddr::new(server.ip(), server.port() + 1);
        assert_eq!(identify(Transport::Tcp, local, other), Caller::unknown());

        // Dual-stack TCP, seen by an IPv4 listener as an IPv4 peer.
        if !ipv6_available() {
            return;
        }
        let v6 = TcpListener::bind("[::]:0").unwrap();
        let v6_server = v6.local_addr().unwrap();
        let mapped_server = addr(&format!("[::ffff:127.0.0.1]:{}", v6_server.port()));
        let client = TcpStream::connect(mapped_server).unwrap();
        let mapped_local = client.local_addr().unwrap();
        let seen_by_listener =
            SocketAddr::new(mapped_local.ip().to_canonical(), mapped_local.port());
        let caller = identify(
            Transport::Tcp,
            seen_by_listener,
            addr(&format!("127.0.0.1:{}", v6_server.port())),
        );
        assert_eq!(caller.uid, Some(unsafe { libc::geteuid() }));
    }

    #[test]
    fn an_unknown_socket_is_an_unknown_caller() {
        let peer = addr("192.0.2.77:1");
        assert_eq!(
            identify(Transport::Udp, peer, addr(SERVER)),
            Caller::unknown()
        );
    }
}
