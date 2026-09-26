//! Relays: users whose lookups a listener passes through unjudged.
//!
//! When front-ends are stacked, one lookup can reach the daemon twice.  With
//! the nscd front-end in place, glibc's host lookups are judged there, with
//! the caller's own credentials, and the ones the policy lets through are
//! forwarded to nsncd, which resolves them through its NSS modules: the
//! deezns NSS module (the policy socket) and `dns` (possibly the DNS
//! front-end).  Judging them again there would see nsncd's credentials and
//! undo per-user rules, so nsncd's user is configured as a relay for those
//! listeners and its lookups are passed through.
//!
//! Users are named in the configuration and resolved to uids once, at
//! startup; a name that does not resolve is a configuration error.

use crate::policy::Caller;

use std::collections::HashSet;
use std::ffi::CString;
use std::io;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Relays {
    uids: HashSet<u32>,
}

impl Relays {
    /// Resolve user names to uids.
    pub fn resolve(users: &[String]) -> io::Result<Self> {
        let uids = users
            .iter()
            .map(|user| {
                uid_of(user)?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("relay user {user:?} does not exist"),
                    )
                })
            })
            .collect::<io::Result<_>>()?;
        Ok(Relays { uids })
    }

    #[cfg(test)]
    pub fn from_uids(uids: impl IntoIterator<Item = u32>) -> Self {
        Relays {
            uids: uids.into_iter().collect(),
        }
    }

    /// Whether the caller is one of the relays.  An unidentified caller
    /// never is.
    pub fn contains(&self, caller: &Caller) -> bool {
        caller.uid.is_some_and(|uid| self.uids.contains(&uid))
    }
}

/// The uid of a user, or `None` if there is no such user.
fn uid_of(user: &str) -> io::Result<Option<u32>> {
    let name = CString::new(user).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut buf = vec![0 as libc::c_char; 1024];
    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer refers to a live, correctly sized buffer.
        let ret = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        match ret {
            0 if result.is_null() => return Ok(None),
            0 => return Ok(Some(pwd.pw_uid)),
            libc::ERANGE => buf.resize(buf.len() * 2, 0),
            errno => return Err(io::Error::from_raw_os_error(errno)),
        }
    }
}

/// The name of the user running this process, for tests.
#[cfg(test)]
fn current_user() -> String {
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: as in `uid_of`.
    let ret = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert!(
        ret == 0 && !result.is_null(),
        "this user has no passwd entry"
    );
    unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_resolve_to_their_uids() {
        let me = unsafe { libc::geteuid() };
        let relays = Relays::resolve(&[current_user()]).unwrap();
        assert!(relays.contains(&Caller::new(me, 0, 1)));
        assert!(!relays.contains(&Caller::new(me.wrapping_add(1), 0, 1)));
        assert!(!relays.contains(&Caller::unknown()));
    }

    #[test]
    fn unknown_users_are_an_error() {
        let err = Relays::resolve(&["deezns-no-such-user".to_string()]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn no_relays_contain_nobody() {
        let relays = Relays::resolve(&[]).unwrap();
        assert!(!relays.contains(&Caller::new(0, 0, 1)));
    }
}
