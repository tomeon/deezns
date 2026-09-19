//! blocklist.rs — parse and query domain blocklists.
//!
//! Supports three common formats:
//!   1. Hosts-file:    `127.0.0.1 ad.example.com` / `0.0.0.0 ad.example.com`
//!   2. Domains-only:  `ad.example.com`  (one domain per line)
//!   3. AdBlock-style: `||ad.example.com^` (domain + all subdomains)
//!
//! Lines starting with `#` or `!` are treated as comments.  Blank lines
//! are ignored.
//!
//! At load time every entry is normalised into a `BlocklistEntry` and
//! stored in a `Blocklist`.  The `Blocklist` is designed to be wrapped
//! in an `Arc` and cheaply shared across tokio tasks.

use std::collections::HashSet;
use std::io::{self, BufRead};
use std::path::Path;
use tracing::warn;

/// A single parsed blocklist entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BlocklistEntry {
    /// Exact domain match (e.g. `ad.example.com`).
    Exact(String),
    /// Domain + all subdomains (e.g. AdBlock `||example.com^` matches
    /// `example.com`, `foo.example.com`, `a.b.example.com`).
    DomainAndSubs(String),
}

/// A loaded blocklist, ready for O(1)-ish lookups.
///
/// We keep two indexes:
///   - `exact`:    HashSet of domains that must match exactly.
///   - `suffixes`: HashSet of domains where any subdomain also matches.
///
/// For suffix matching we check the queried hostname and each of its
/// parent domains against `suffixes`.  With typical blocklists (100k–1M
/// entries) this is fast because the number of labels in a hostname is
/// small (usually ≤ 6).
#[derive(Debug, Clone)]
pub struct Blocklist {
    exact: HashSet<String>,
    suffixes: HashSet<String>,
    /// Human-readable name (e.g. "StevenBlack hosts", "oisd").
    pub name: String,
}

impl Blocklist {
    /// Load a blocklist from a file, auto-detecting the format.
    pub fn load(path: &Path, name: impl Into<String>) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        Ok(Self::parse(reader, name))
    }

    /// Parse a blocklist from any `BufRead` source.
    pub fn parse(reader: impl BufRead, name: impl Into<String>) -> Self {
        let mut exact = HashSet::new();
        let mut suffixes = HashSet::new();

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            let line = line.trim();

            // Skip blanks and comments.
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }

            match Self::parse_line(line) {
                Some(BlocklistEntry::Exact(d)) => {
                    exact.insert(d);
                }
                Some(BlocklistEntry::DomainAndSubs(d)) => {
                    suffixes.insert(d);
                }
                None => {
                    // Unparseable line — skip silently in production;
                    // warn in debug builds.
                    warn!(line, "skipping unparseable blocklist line");
                }
            }
        }

        Self {
            exact,
            suffixes,
            name: name.into(),
        }
    }

    /// Returns `true` if `hostname` is blocked by this list.
    pub fn contains(&self, hostname: &str) -> bool {
        let hostname = hostname.to_ascii_lowercase();

        // 1. Exact match.
        if self.exact.contains(&hostname) {
            return true;
        }

        // 2. Suffix / domain-and-subs match.
        //    Check the full hostname, then strip one label at a time.
        if self.suffixes.contains(&hostname) {
            return true;
        }
        let mut rest = hostname.as_str();
        while let Some(pos) = rest.find('.') {
            rest = &rest[pos + 1..];
            if self.suffixes.contains(rest) {
                return true;
            }
        }

        false
    }

    /// Total number of entries.
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // ── Line parser ──────────────────────────────────────────────────

    fn parse_line(line: &str) -> Option<BlocklistEntry> {
        // AdBlock-style: ||example.com^  or  ||example.com|
        if let Some(rest) = line.strip_prefix("||") {
            let domain = rest.trim_end_matches(|c| c == '^' || c == '|');
            let domain = domain.trim().to_ascii_lowercase();
            if Self::is_valid_domain(&domain) {
                return Some(BlocklistEntry::DomainAndSubs(domain));
            }
            return None;
        }

        // AdBlock exception (@@||...): skip — we don't model exceptions
        // at the blocklist layer; use a CEL rule to allowlist instead.
        if line.starts_with("@@") {
            return None;
        }

        // Hosts-file style: `<ip> <domain>` — possibly with trailing comment.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() >= 2 && Self::looks_like_ip(tokens[0]) {
            let domain = tokens[1].to_ascii_lowercase();
            if Self::is_valid_domain(&domain) && domain != "localhost" {
                return Some(BlocklistEntry::Exact(domain));
            }
            return None;
        }

        // Domains-only: bare domain name, one per line.
        if tokens.len() == 1 {
            let domain = tokens[0].to_ascii_lowercase();
            if Self::is_valid_domain(&domain) {
                return Some(BlocklistEntry::Exact(domain));
            }
        }

        None
    }

    fn looks_like_ip(s: &str) -> bool {
        // Quick heuristic: starts with a digit or contains ':' (v6).
        s.starts_with(|c: char| c.is_ascii_digit()) || s.contains(':')
    }

    fn is_valid_domain(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 253
            && s.contains('.')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn bl(input: &str) -> Blocklist {
        Blocklist::parse(io::Cursor::new(input), "test")
    }

    #[test]
    fn hosts_file_format() {
        let list = bl("127.0.0.1 ad.example.com\n0.0.0.0 tracker.example.net\n");
        assert!(list.contains("ad.example.com"));
        assert!(list.contains("tracker.example.net"));
        assert!(!list.contains("example.com"));
        assert!(!list.contains("sub.ad.example.com"));
    }

    #[test]
    fn domains_only_format() {
        let list = bl("ad.example.com\ntracker.example.net\n");
        assert!(list.contains("ad.example.com"));
        assert!(!list.contains("sub.ad.example.com"));
    }

    #[test]
    fn adblock_format() {
        let list = bl("||example.com^\n||tracker.net^\n");
        assert!(list.contains("example.com"));
        assert!(list.contains("sub.example.com"));
        assert!(list.contains("a.b.c.example.com"));
        assert!(list.contains("tracker.net"));
        assert!(!list.contains("notexample.com"));
    }

    #[test]
    fn comments_and_blanks() {
        let list = bl("# comment\n! another comment\n\n||ad.test^\n");
        assert_eq!(list.len(), 1);
        assert!(list.contains("ad.test"));
    }

    #[test]
    fn case_insensitive() {
        let list = bl("||Ad.Example.COM^\n");
        assert!(list.contains("ad.example.com"));
        assert!(list.contains("AD.EXAMPLE.COM"));
        assert!(list.contains("Sub.Ad.Example.Com"));
    }

    #[test]
    fn adblock_exceptions_skipped() {
        let list = bl("||example.com^\n@@||example.com^\n");
        // We only see the block rule, not the exception.
        assert_eq!(list.suffixes.len(), 1);
    }

    #[test]
    fn localhost_skipped() {
        let list = bl("127.0.0.1 localhost\n");
        assert!(list.is_empty());
    }
}
