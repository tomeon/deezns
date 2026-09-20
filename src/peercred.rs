//! `SO_PEERCRED`: who is on the other end of a Unix stream socket.

use crate::policy::Caller;

use std::io;
use std::os::unix::io::AsRawFd;

/// The credentials the kernel recorded for the peer when it connected:
/// its process id and effective user and group ids at that moment.
pub fn peer_caller<S: AsRawFd>(stream: &S) -> io::Result<Caller> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: fd is a valid socket and `cred`/`len` are correctly sized.
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

    Ok(Caller::new(cred.uid, cred.gid, cred.pid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn peer_of_a_socket_pair_is_this_process() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let caller = peer_caller(&ours).unwrap();
        assert_eq!(caller.uid, Some(unsafe { libc::geteuid() }));
        assert_eq!(caller.gid, Some(unsafe { libc::getegid() }));
        assert_eq!(caller.pid, Some(std::process::id() as i32));
    }
}
