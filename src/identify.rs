//! Who owns a local IP socket?
//!
//! A DNS query arriving over loopback carries no credentials, but the
//! kernel knows which socket it left from.  `/proc/net/{udp,udp6,tcp,tcp6}`
//! list every socket with its local address, the uid of its owner and its
//! inode; the uid is readable by anyone.  Turning the inode into a process
//! (and from there into a gid) means finding it among `/proc/<pid>/fd`.
//! Another user's fd directory is mode 0500 and owned by that user, so
//! listing it needs `CAP_DAC_READ_SEARCH`, and following its links needs
//! `CAP_SYS_PTRACE` (this is why `ss -p` wants root).  Without both, the
//! caller is identified by uid alone and `gid` and `pid` stay unknown.

use crate::policy::Caller;

use std::net::SocketAddr;
use std::sync::OnceLock;

use procfs::process::{all_processes, FDTarget, Process};
use tracing::{debug, info};

/// The transport a query arrived over, which decides the socket table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// A row of a socket table: the local address, the owner and the inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub local: SocketAddr,
    pub uid: u32,
    pub inode: u64,
}

fn socket_table(transport: Transport, ipv6: bool) -> procfs::ProcResult<Vec<SocketEntry>> {
    let entry = |local: SocketAddr, uid: u32, inode: u64| SocketEntry { local, uid, inode };
    Ok(match (transport, ipv6) {
        (Transport::Udp, false) => procfs::net::udp()?
            .into_iter()
            .map(|e| entry(e.local_address, e.uid, e.inode))
            .collect(),
        (Transport::Udp, true) => procfs::net::udp6()?
            .into_iter()
            .map(|e| entry(e.local_address, e.uid, e.inode))
            .collect(),
        (Transport::Tcp, false) => procfs::net::tcp()?
            .into_iter()
            .map(|e| entry(e.local_address, e.uid, e.inode))
            .collect(),
        (Transport::Tcp, true) => procfs::net::tcp6()?
            .into_iter()
            .map(|e| entry(e.local_address, e.uid, e.inode))
            .collect(),
    })
}

/// The table row for the socket a packet from `peer` came out of.
///
/// An unconnected UDP socket is listed with an unspecified address
/// (`0.0.0.0:port`), so the match is on the port and, when the table has
/// one, the address.
pub fn find_socket(entries: &[SocketEntry], peer: SocketAddr) -> Option<&SocketEntry> {
    entries
        .iter()
        .filter(|e| e.local.port() == peer.port())
        .find(|e| e.local.ip() == peer.ip() || e.local.ip().is_unspecified())
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

/// Identify the process that sent from `peer` over `transport`: uid from
/// the socket table, and gid and pid when the owning process can be found.
pub fn identify(transport: Transport, peer: SocketAddr) -> Caller {
    let entries = match socket_table(transport, peer.is_ipv6()) {
        Ok(entries) => entries,
        Err(e) => {
            debug!(%e, "cannot read socket table");
            return Caller::unknown();
        }
    };
    let Some(socket) = find_socket(&entries, peer) else {
        debug!(%peer, "no local socket matches the peer address");
        return Caller::unknown();
    };

    let process = process_with_socket(socket.inode);
    let pid = process.as_ref().map(|p| p.pid());
    let gid = process.and_then(|p| p.status().ok()).map(|s| s.egid);
    Caller {
        uid: Some(socket.uid),
        gid,
        pid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};

    fn entry(local: &str, uid: u32, inode: u64) -> SocketEntry {
        SocketEntry {
            local: local.parse().unwrap(),
            uid,
            inode,
        }
    }

    #[test]
    fn sockets_match_on_port_and_address_or_wildcard() {
        let entries = [
            entry("0.0.0.0:5000", 1000, 1),
            entry("127.0.0.1:5001", 1001, 2),
            entry("10.0.0.1:5001", 1002, 3),
        ];
        let peer = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(
            find_socket(&entries, peer("127.0.0.1:5000")).map(|e| e.inode),
            Some(1)
        );
        assert_eq!(
            find_socket(&entries, peer("127.0.0.1:5001")).map(|e| e.inode),
            Some(2)
        );
        assert_eq!(
            find_socket(&entries, peer("10.0.0.1:5001")).map(|e| e.inode),
            Some(3)
        );
        assert_eq!(find_socket(&entries, peer("192.0.2.1:5001")), None);
        assert_eq!(find_socket(&entries, peer("127.0.0.1:5002")), None);
    }

    #[test]
    fn our_own_udp_socket_is_identified_fully() {
        // A connected UDP socket, as glibc's resolver makes: listed with its
        // local address.
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.connect((Ipv4Addr::LOCALHOST, 53)).unwrap();
        let local = socket.local_addr().unwrap();

        let caller = identify(Transport::Udp, local);
        assert_eq!(caller.uid, Some(unsafe { libc::geteuid() }));
        // Our own fd table is always readable, so the process is found.
        assert_eq!(caller.pid, Some(std::process::id() as i32));
        assert_eq!(caller.gid, Some(unsafe { libc::getegid() }));
    }

    #[test]
    fn our_own_tcp_socket_is_identified_fully() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let local = client.local_addr().unwrap();

        let caller = identify(Transport::Tcp, local);
        assert_eq!(caller.uid, Some(unsafe { libc::geteuid() }));
        assert_eq!(caller.pid, Some(std::process::id() as i32));
    }

    #[test]
    fn an_unknown_socket_is_an_unknown_caller() {
        // Nothing of ours listens on this ephemeral-looking port with that
        // address, so there is nothing to identify.
        let peer: SocketAddr = "192.0.2.77:1".parse().unwrap();
        assert_eq!(identify(Transport::Udp, peer), Caller::unknown());
    }
}
