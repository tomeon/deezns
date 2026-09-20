//! policy.rs — CEL-based policy engine with blocklist support.
//!
//! # Config layout (TOML)
//!
//! ```toml
//! default_verdict = "passthrough"   # or "deny"
//!
//! # External blocklists (hosts-file, domains-only, or AdBlock-style).
//! # Each is loaded once at startup and exposed to CEL as a function.
//! [[blocklists]]
//! name = "stevenblack"
//! path = "/etc/deezns/lists/stevenblack-hosts.txt"
//!
//! [[blocklists]]
//! name = "oisd"
//! path = "/etc/deezns/lists/oisd-abp.txt"
//!
//! # Ordered rules.  First match wins.
//! # Each rule has a CEL expression and a verdict.
//! # Available CEL variables:
//! #   hostname  : string   — queried hostname (lowercase)
//! #   uid       : int      — peer UID from SO_PEERCRED
//! #   gid       : int      — peer GID
//! #   pid       : int      — peer PID
//! #
//! # Available CEL functions:
//! #   blocked_by(list_name: string) : bool
//! #       — returns true if `hostname` appears in the named blocklist.
//! #   hostname.endsWith(suffix)     — built-in CEL string method.
//! #   hostname.startsWith(prefix)   — built-in CEL string method.
//! #   hostname.contains(sub)        — built-in CEL string method.
//! #   hostname.matches(re)          — regex (requires `regex` feature).
//!
//! [[rules]]
//! note = "Global adblock deny"
//! expr = 'blocked_by("stevenblack") || blocked_by("oisd")'
//! verdict = "deny"
//!
//! [[rules]]
//! note = "Dev user allowlist"
//! expr = '''
//!   uid == 1000 && (
//!     hostname.endsWith(".github.com") ||
//!     hostname == "github.com" ||
//!     hostname == "crates.io"
//!   )
//! '''
//! verdict = "allow"
//!
//! [[rules]]
//! note = "Root can go anywhere not adblocked"
//! expr = "uid == 0"
//! verdict = "allow"
//! ```

use crate::blocklist::Blocklist;
use cel_interpreter::{Context, Program, Value};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;

// ---------------------------------------------------------------------------
// Config types (deserialized from TOML)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultVerdict {
    /// No opinion — let the next NSS source handle it.
    Passthrough,
    /// Deny everything not explicitly allowed.
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerdict {
    Allow,
    Deny,
    Passthrough,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    /// Human-readable note (for logging and diagnostics).
    #[serde(default)]
    pub note: String,
    /// CEL expression that must evaluate to `true` for this rule to fire.
    pub expr: String,
    /// What to do when the expression matches.
    pub verdict: RuleVerdict,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistConfig {
    /// Logical name — referenced in CEL as `blocked_by("name")`.
    pub name: String,
    /// Path to the list file on disk.
    pub path: PathBuf,
}

/// The nscd-protocol front-end (see `nscd.rs`): deezns answers on the socket
/// glibc's nscd client uses, applies the policy to host lookups with the
/// real caller's credentials, and forwards everything else to the actual
/// nscd listening at `upstream`.
#[derive(Debug, Clone, Deserialize)]
pub struct NscdFrontendConfig {
    /// Where to listen; glibc looks at `/var/run/nscd/socket`.
    pub listen: PathBuf,
    /// The real nscd (nsncd's `NSNCD_SOCKET_PATH`) that serves everything
    /// deezns does not answer itself.
    pub upstream: PathBuf,
}

/// The DNS front-end (see `dns.rs`): deezns answers DNS on a loopback
/// address, identifies callers from their sockets, and forwards what it does
/// not answer itself to `upstream`.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsFrontendConfig {
    /// Address and port to serve DNS on, over UDP and TCP.
    pub listen: SocketAddr,
    /// The real DNS server for names the policy lets through.
    pub upstream: SocketAddr,
    /// How long to wait for the upstream before answering SERVFAIL.
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
}

fn default_upstream_timeout_ms() -> u64 {
    5000
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_passthrough")]
    pub default_verdict: DefaultVerdict,

    #[serde(default)]
    pub blocklists: Vec<BlocklistConfig>,

    #[serde(default)]
    pub rules: Vec<RuleConfig>,

    #[serde(default)]
    pub nscd_frontend: Option<NscdFrontendConfig>,

    #[serde(default)]
    pub dns_frontend: Option<DnsFrontendConfig>,
}

impl PolicyConfig {
    /// Read and parse the configuration file.
    pub fn from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }
}

/// Who is asking, as far as the daemon can tell.
///
/// `SO_PEERCRED` gives all three.  Front-ends that learn about the caller
/// indirectly may know only the uid, or nothing at all; whatever is unknown
/// is exposed to CEL as `-1`, which no real uid, gid or pid equals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub pid: Option<i32>,
}

impl Caller {
    pub fn new(uid: u32, gid: u32, pid: i32) -> Self {
        Caller {
            uid: Some(uid),
            gid: Some(gid),
            pid: Some(pid),
        }
    }

    /// A caller nothing is known about.
    pub fn unknown() -> Self {
        Caller {
            uid: None,
            gid: None,
            pid: None,
        }
    }

    /// The value a CEL rule sees for `uid`.
    pub fn uid_value(&self) -> i64 {
        self.uid.map_or(-1, i64::from)
    }

    /// The value a CEL rule sees for `gid`.
    pub fn gid_value(&self) -> i64 {
        self.gid.map_or(-1, i64::from)
    }

    /// The value a CEL rule sees for `pid`.
    pub fn pid_value(&self) -> i64 {
        self.pid.map_or(-1, i64::from)
    }
}

fn default_passthrough() -> DefaultVerdict {
    DefaultVerdict::Passthrough
}

// ---------------------------------------------------------------------------
// Compiled policy engine
// ---------------------------------------------------------------------------

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    Denied(String),
    PassThrough,
    Allowed,
}

/// A single rule with its CEL program pre-compiled.
struct CompiledRule {
    note: String,
    program: Program,
    verdict: RuleVerdict,
}

/// The fully loaded, compiled policy engine.  Designed to live inside
/// an `Arc` and be shared across tokio tasks.
pub struct PolicyEngine {
    rules: Vec<CompiledRule>,
    blocklists: HashMap<String, Arc<Blocklist>>,
    default_verdict: DefaultVerdict,
}

impl PolicyEngine {
    /// Parse all blocklists and compile all CEL expressions of a parsed
    /// configuration (see [`PolicyConfig::from_path`] for the file).
    pub fn from_config(cfg: &PolicyConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Load blocklists.
        let mut blocklists = HashMap::new();
        for bl_cfg in &cfg.blocklists {
            let bl = Blocklist::load(&bl_cfg.path, &bl_cfg.name)?;
            info!(
                name = bl_cfg.name,
                path = %bl_cfg.path.display(),
                entries = bl.len(),
                "loaded blocklist"
            );
            blocklists.insert(bl_cfg.name.clone(), Arc::new(bl));
        }

        // Compile CEL rules.
        let mut rules = Vec::with_capacity(cfg.rules.len());
        for (i, rule_cfg) in cfg.rules.iter().enumerate() {
            let program = Program::compile(&rule_cfg.expr)
                .map_err(|e| format!("rule {} ({:?}): CEL compile error: {e}", i, rule_cfg.note))?;
            rules.push(CompiledRule {
                note: rule_cfg.note.clone(),
                program,
                verdict: rule_cfg.verdict.clone(),
            });
        }

        info!(
            rules = rules.len(),
            blocklists = blocklists.len(),
            "policy engine ready"
        );

        Ok(Self {
            rules,
            blocklists,
            default_verdict: cfg.default_verdict.clone(),
        })
    }

    /// Evaluate the policy for a query from a fully identified caller.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn evaluate(&self, hostname: &str, uid: u32, gid: u32, pid: i32) -> PolicyVerdict {
        self.evaluate_for(hostname, &Caller::new(uid, gid, pid))
    }

    /// Evaluate the policy for a given query.
    pub fn evaluate_for(&self, hostname: &str, caller: &Caller) -> PolicyVerdict {
        let hostname_lower = hostname.to_ascii_lowercase();

        // Pre-compute blocklist membership so we can expose it as a
        // simple function to CEL.  The map is owned (not borrowed from
        // `self`) because `Context::add_function` requires a `'static`
        // closure; wrapping it in an `Arc` keeps the per-rule clone cheap.
        let bl_results: Arc<HashMap<String, bool>> = Arc::new(
            self.blocklists
                .iter()
                .map(|(name, bl)| (name.clone(), bl.contains(&hostname_lower)))
                .collect(),
        );

        // Build the CEL context.  We create a fresh one per evaluation;
        // the overhead is trivial (a few HashMap inserts) compared to
        // the socket I/O that got us here.
        for rule in &self.rules {
            let mut ctx = Context::default();

            // Variables.
            ctx.add_variable("hostname", hostname_lower.clone())
                .unwrap();
            ctx.add_variable("uid", caller.uid_value()).unwrap();
            ctx.add_variable("gid", caller.gid_value()).unwrap();
            ctx.add_variable("pid", caller.pid_value()).unwrap();

            // blocked_by("list_name") → bool
            //
            // We capture a snapshot of the pre-computed results so CEL
            // doesn't need access to the Blocklist at eval time.
            let bl_snapshot = Arc::clone(&bl_results);
            ctx.add_function("blocked_by", move |name: Arc<String>| {
                bl_snapshot.get(name.as_str()).copied().unwrap_or(false)
            });

            match rule.program.execute(&ctx) {
                Ok(Value::Bool(true)) => {
                    return match &rule.verdict {
                        RuleVerdict::Allow => PolicyVerdict::Allowed,
                        RuleVerdict::Deny => {
                            PolicyVerdict::Denied(format!("matched rule: {}", rule.note))
                        }
                        RuleVerdict::Passthrough => PolicyVerdict::PassThrough,
                    };
                }
                Ok(_) => continue, // expression was false / non-bool
                Err(e) => {
                    tracing::error!(
                        rule = rule.note,
                        %e,
                        "CEL evaluation error, skipping rule"
                    );
                    continue;
                }
            }
        }

        // No rule matched — apply default.
        match self.default_verdict {
            DefaultVerdict::Passthrough => PolicyVerdict::PassThrough,
            DefaultVerdict::Deny => {
                PolicyVerdict::Denied(format!("{hostname_lower} denied by default policy"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (unit-level, no files needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a PolicyEngine from an inline TOML string (no
    /// blocklist files).
    fn engine_from_toml(toml_str: &str) -> PolicyEngine {
        let cfg: PolicyConfig = toml::from_str(toml_str).unwrap();
        let mut rules = Vec::new();
        for rule_cfg in &cfg.rules {
            let program = Program::compile(&rule_cfg.expr).unwrap();
            rules.push(CompiledRule {
                note: rule_cfg.note.clone(),
                program,
                verdict: rule_cfg.verdict.clone(),
            });
        }
        PolicyEngine {
            rules,
            blocklists: HashMap::new(),
            default_verdict: cfg.default_verdict,
        }
    }

    #[test]
    fn first_matching_rule_wins() {
        let engine = engine_from_toml(
            r#"
            default_verdict = "passthrough"

            [[rules]]
            note = "deny tiktok for uid 1000"
            expr = 'uid == 1000 && hostname.endsWith(".tiktok.com")'
            verdict = "deny"

            [[rules]]
            note = "allow everything for uid 1000"
            expr = "uid == 1000"
            verdict = "allow"
        "#,
        );

        // tiktok.com hits the first rule → deny
        assert!(matches!(
            engine.evaluate("www.tiktok.com", 1000, 1000, 42),
            PolicyVerdict::Denied(_)
        ));

        // github.com skips rule 1, hits rule 2 → allow
        assert_eq!(
            engine.evaluate("github.com", 1000, 1000, 42),
            PolicyVerdict::Allowed,
        );
    }

    #[test]
    fn default_deny_catches_unmatched() {
        let engine = engine_from_toml(
            r#"
            default_verdict = "deny"

            [[rules]]
            note = "only root"
            expr = "uid == 0"
            verdict = "allow"
        "#,
        );

        assert_eq!(
            engine.evaluate("anything.com", 0, 0, 1),
            PolicyVerdict::Allowed,
        );
        assert!(matches!(
            engine.evaluate("anything.com", 1000, 1000, 99),
            PolicyVerdict::Denied(_)
        ));
    }

    #[test]
    fn default_passthrough_falls_through() {
        let engine = engine_from_toml(
            r#"
            default_verdict = "passthrough"
            rules = []
        "#,
        );

        assert_eq!(
            engine.evaluate("example.com", 1000, 1000, 1),
            PolicyVerdict::PassThrough,
        );
    }

    #[test]
    fn unknown_gid_and_pid_are_minus_one() {
        let engine = engine_from_toml(
            r#"
            default_verdict = "deny"

            [[rules]]
            note = "gid known"
            expr = "gid == 100"
            verdict = "allow"

            [[rules]]
            note = "gid unknown"
            expr = "gid == -1 && pid == -1"
            verdict = "passthrough"
        "#,
        );

        let known = Caller::new(1000, 100, 7);
        assert_eq!(
            engine.evaluate_for("a.test", &known),
            PolicyVerdict::Allowed
        );

        let unknown = Caller {
            uid: Some(1000),
            gid: None,
            pid: None,
        };
        assert_eq!(
            engine.evaluate_for("a.test", &unknown),
            PolicyVerdict::PassThrough
        );
        assert_eq!(unknown.uid_value(), 1000);
        assert_eq!(unknown.gid_value(), -1);
        assert_eq!(unknown.pid_value(), -1);

        let nobody = Caller::unknown();
        assert_eq!(nobody.uid_value(), -1);
        assert_eq!(
            engine.evaluate_for("a.test", &nobody),
            PolicyVerdict::PassThrough
        );
    }

    #[test]
    fn dns_frontend_section_is_optional_with_a_default_timeout() {
        let cfg: PolicyConfig = toml::from_str(r#"default_verdict = "deny""#).unwrap();
        assert!(cfg.dns_frontend.is_none());

        let cfg: PolicyConfig = toml::from_str(
            r#"
            [dns_frontend]
            listen = "127.0.0.1:53"
            upstream = "192.0.2.53:53"
        "#,
        )
        .unwrap();
        let front = cfg.dns_frontend.unwrap();
        assert_eq!(front.listen, "127.0.0.1:53".parse::<SocketAddr>().unwrap());
        assert_eq!(
            front.upstream,
            "192.0.2.53:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(front.upstream_timeout_ms, 5000);
    }

    #[test]
    fn nscd_frontend_section_is_optional() {
        let cfg: PolicyConfig = toml::from_str(r#"default_verdict = "deny""#).unwrap();
        assert!(cfg.nscd_frontend.is_none());

        let cfg: PolicyConfig = toml::from_str(
            r#"
            [nscd_frontend]
            listen = "/run/nscd/socket"
            upstream = "/run/nsncd/socket"
        "#,
        )
        .unwrap();
        let front = cfg.nscd_frontend.unwrap();
        assert_eq!(front.listen, PathBuf::from("/run/nscd/socket"));
        assert_eq!(front.upstream, PathBuf::from("/run/nsncd/socket"));
    }

    #[test]
    fn cel_string_methods_work() {
        let engine = engine_from_toml(
            r#"
            default_verdict = "passthrough"

            [[rules]]
            note = "block .local"
            expr = 'hostname.endsWith(".local") || hostname == "local"'
            verdict = "deny"

            [[rules]]
            note = "block internal prefix"
            expr = 'hostname.startsWith("internal-")'
            verdict = "deny"

            [[rules]]
            note = "block anything with 'tracking'"
            expr = 'hostname.contains("tracking")'
            verdict = "deny"
        "#,
        );

        assert!(matches!(
            engine.evaluate("foo.local", 0, 0, 1),
            PolicyVerdict::Denied(_)
        ));
        assert!(matches!(
            engine.evaluate("internal-api.corp.com", 0, 0, 1),
            PolicyVerdict::Denied(_)
        ));
        assert!(matches!(
            engine.evaluate("user-tracking.example.com", 0, 0, 1),
            PolicyVerdict::Denied(_)
        ));
        assert_eq!(
            engine.evaluate("safe.example.com", 0, 0, 1),
            PolicyVerdict::PassThrough,
        );
    }
}
