//! Relays: users whose lookups a listener passes through unjudged.
//!
//! When front-ends are stacked, one lookup can reach the daemon more than
//! once, in this order:
//!
//! ```text
//! glibc -> [nscd front-end] -> nscd -> [NSS module] -> dns -> [DNS front-end]
//! ```
//!
//! The nscd front-end judges glibc's host lookups with the caller's own
//! credentials and forwards the ones the policy lets through to nscd, which
//! resolves them through its NSS modules: the deezns NSS module (the policy
//! socket) and `dns` (possibly the DNS front-end).  Judging them again there
//! would see nscd's credentials and undo per-user rules.  So nscd's user
//! (`nscd_user`) is a relay on the policy socket when the nscd front-end is
//! enabled, and on the DNS front-end when the nscd front-end or the NSS
//! module is (the NSS module comes before `dns`); its lookups there pass
//! through.  Programs with their own DNS client still meet the DNS
//! front-end first.
//!
//! The user is resolved to a uid once, at startup; a name that does not
//! resolve is a configuration error.

use crate::policy::{Caller, PolicyConfig};

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

/// The relays of the listeners that can sit behind another front-end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerRelays {
    pub policy_socket: Relays,
    pub dns: Relays,
}

/// Whether nscd is a relay on the policy socket and on the DNS front-end.
fn relaying(cfg: &PolicyConfig) -> (bool, bool) {
    let nscd = cfg.nscd().is_some();
    (nscd, nscd || cfg.nss())
}

impl ListenerRelays {
    pub fn for_config(cfg: &PolicyConfig) -> io::Result<Self> {
        let (policy_socket, dns) = relaying(cfg);
        let nscd = match &cfg.nscd_user {
            Some(user) if policy_socket || dns => Relays::resolve(std::slice::from_ref(user))?,
            _ => Relays::default(),
        };
        let only_if = |on: bool| if on { nscd.clone() } else { Relays::default() };
        Ok(ListenerRelays {
            policy_socket: only_if(policy_socket),
            dns: only_if(dns),
        })
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

    fn config(toml: &str) -> PolicyConfig {
        toml::from_str(toml).unwrap()
    }

    const NSCD: &str = "[nscd_frontend]\nlisten = \"/a\"\nupstream = \"/b\"\n";
    const NSS: &str = "[nss_frontend]\n";

    #[test]
    fn nscd_relays_behind_the_front_ends_before_it() {
        assert_eq!(relaying(&config("")), (false, false));
        assert_eq!(relaying(&config(NSS)), (false, true));
        assert_eq!(relaying(&config(NSCD)), (true, true));
        assert_eq!(relaying(&config(&format!("{NSCD}{NSS}"))), (true, true));
        let disabled = format!("{NSCD}enable = false\n{NSS}enable = false\n");
        assert_eq!(relaying(&config(&disabled)), (false, false));
    }

    #[test]
    fn nscd_user_is_resolved_for_the_listeners_that_relay() {
        let me = Caller::new(unsafe { libc::geteuid() }, 0, 1);
        let user = format!("nscd_user = {:?}\n", current_user());

        let relays = ListenerRelays::for_config(&config(&format!("{user}{NSS}"))).unwrap();
        assert!(!relays.policy_socket.contains(&me));
        assert!(relays.dns.contains(&me));

        let relays = ListenerRelays::for_config(&config(&format!("{user}{NSCD}"))).unwrap();
        assert!(relays.policy_socket.contains(&me));
        assert!(relays.dns.contains(&me));

        // No front-end in front of anything: the user is not even looked up.
        let nobody = "nscd_user = \"deezns-no-such-user\"\n";
        assert_eq!(
            ListenerRelays::for_config(&config(nobody)).unwrap(),
            ListenerRelays::default()
        );
        assert!(ListenerRelays::for_config(&config(&format!("{nobody}{NSS}"))).is_err());
        // Without nscd_user nobody relays.
        assert_eq!(
            ListenerRelays::for_config(&config(NSCD)).unwrap(),
            ListenerRelays::default()
        );
    }

    #[test]
    fn no_relays_contain_nobody() {
        let relays = Relays::resolve(&[]).unwrap();
        assert!(!relays.contains(&Caller::new(0, 0, 1)));
    }
}
