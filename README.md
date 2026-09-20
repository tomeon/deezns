# deezns — per-UID DNS policy daemon with CEL rules and blocklist support

A Rust project demonstrating:

1. **A tokio-based daemon** (`deezns-daemon`) that listens on a Unix domain
   socket, uses `SO_PEERCRED` to identify the calling process, and evaluates
   a CEL-based policy to allow, deny, or pass through DNS lookups.

2. **An NSS module** (`libnss_deezns.so.2`) that glibc loads automatically
   for `gethostbyname` / `getaddrinfo`.

3. **A blocklist loader** that parses hosts-file, domains-only, and
   AdBlock-style (`||domain^`) filter lists and exposes them to CEL as
   `blocked_by("list_name")`.

## Architecture

```
 ┌────────────────────────────────┐
 │  any process (curl, ping, …)   │
 │  calls getaddrinfo()           │
 └──────────┬─────────────────────┘
            │  glibc NSS
            ▼
 ┌────────────────────────────────┐
 │  libnss_deezns.so.2            │  ← src/lib.rs
 │  blocking UDS client           │
 └──────────┬─────────────────────┘
            │  AF_UNIX stream
            ▼
 ┌────────────────────────────────┐
 │  deezns-daemon (tokio)         │  ← src/daemon.rs
 │                                │
 │  SO_PEERCRED → pid/uid/gid     │
 │        │                       │
 │        ▼                       │
 │  ┌──────────────────────┐      │
 │  │  PolicyEngine         │     │
 │  │                       │     │
 │  │  Blocklists (HashSet) │     │  ← src/blocklist.rs
 │  │  CEL rules (compiled) │     │  ← src/policy.rs
 │  │  blocked_by("name")   │     │
 │  └──────────────────────┘      │
 │        │                       │
 │        ▼                       │
 │  Denied / PassThrough / Resolved│
 └────────────────────────────────┘
```

## Policy configuration

Policy is defined in a TOML file (default: `/etc/deezns/policy.toml`).

### CEL variables

Every rule expression has access to:

| Variable   | Type   | Description                   |
| ---------- | ------ | ----------------------------- |
| `hostname` | string | Queried hostname (lowercased) |
| `uid`      | int    | Peer UID from SO_PEERCRED     |
| `gid`      | int    | Peer GID                      |
| `pid`      | int    | Peer PID                      |

### CEL functions

| Function                  | Returns | Description                                |
| ------------------------- | ------- | ------------------------------------------ |
| `blocked_by("list_name")` | bool    | True if hostname is in the named blocklist |

Plus all built-in CEL string methods: `endsWith`, `startsWith`, `contains`,
`matches` (regex, requires the `regex` feature on `cel-interpreter`).

### Verdicts

| Verdict       | NSS behaviour                                |
| ------------- | -------------------------------------------- |
| `deny`        | NXDOMAIN — stops the NSS chain               |
| `passthrough` | Return UNAVAIL — glibc tries the next source |
| `allow`       | Proceed with upstream resolution             |

Rules are evaluated in order; **first match wins**.

Before evaluation the queried name is canonicalised: lower-cased and
stripped of any trailing dot, so `Blocked.Test.` and `blocked.test` are
the same name to every rule and blocklist. A query for the DNS root
reaches the rules as `"."`.

### Blocklist formats

The blocklist loader (`src/blocklist.rs`) auto-detects three formats:

- **Hosts-file**: `127.0.0.1 ad.example.com` (exact match)
- **Domains-only**: `ad.example.com` (exact match)
- **AdBlock-style**: `||example.com^` (domain + all subdomains)

This means you can point it at lists from StevenBlack/hosts, oisd, or any
AdGuard/uBlock-compatible domain blocklist. AdBlock exception rules
(`@@||...`) are intentionally ignored at the blocklist layer — use a CEL
rule with `verdict = "allow"` to create exceptions.

### Example config

```toml
default_verdict = "deny"

[[blocklists]]
name = "stevenblack"
path = "/etc/deezns/lists/stevenblack-hosts.txt"

[[rules]]
note = "Block ads for everyone"
expr = 'blocked_by("stevenblack")'
verdict = "deny"

[[rules]]
note = "Root gets full access"
expr = "uid == 0"
verdict = "allow"

[[rules]]
note = "Dev user allowlist"
expr = '''
  uid == 1000 && (
    hostname == "github.com" ||
    hostname.endsWith(".github.com")
  )
'''
verdict = "allow"
```

## Building

```bash
cargo build --release
```

## Installing

```bash
sudo install -m 755 target/release/deezns-daemon /usr/local/bin/
sudo install -m 644 target/release/libnss_deezns.so /usr/lib/libnss_deezns.so.2
sudo ldconfig
```

Edit `/etc/nsswitch.conf`:

```
hosts: files deezns [!UNAVAIL=return] dns
```

The `[!UNAVAIL=return]` action tells glibc: if deezns returns UNAVAIL
(our "pass through" signal), continue to the next source.

## Running

```bash
sudo mkdir -p /run/deezns /etc/deezns/lists
# Download a blocklist:
curl -o /etc/deezns/lists/stevenblack-hosts.txt \
  https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
# Write your policy.toml (see config/policy.toml for an example)
# Start the daemon:
RUST_LOG=info deezns-daemon
```

## Running behind nscd

On systems where glibc routes lookups through nscd, which includes every
NixOS system (it runs [nsncd](https://github.com/twosigma/nsncd) and
loads third-party NSS modules only there), an NSS module never sees the
process that asked: the module runs inside nscd, so `SO_PEERCRED` on the
daemon's socket reports nscd's uid, gid and pid for every lookup.

The daemon can instead take nscd's place on the wire. With an
`[nscd_frontend]` section in the policy it listens on the socket glibc's
client uses, applies the policy to host requests (`GETAI`,
`GETHOSTBYNAME`, `GETHOSTBYNAMEv6`) with the credentials of the process
that connected, and forwards everything else, passwd and group lookups
included, byte for byte to the real nscd on another socket:

```toml
[nscd_frontend]
listen = "/run/nscd/socket"      # where glibc looks (_PATH_NSCDSOCKET)
upstream = "/run/nsncd/socket"   # nsncd, started with NSNCD_SOCKET_PATH
```

In this mode the NSS module and the `deezns` line in `nsswitch.conf`
are not needed; an allowed name is resolved by nscd through the normal
`files` and `dns` sources. Denials are answered as "host not found"
(never as "database not served", which would make glibc bypass nscd
for its next hundred lookups). Whatever the real nscd sends back for a
host lookup is checked to be a complete, well-formed reply before it is
relayed; an nscd that is unreachable, silent, slow or answers "not
served" yields a temporary failure instead, so the client keeps using
nscd. Other requests fall back to glibc's built-in sources. Reverse
lookups carry an address rather than a name and are forwarded
unfiltered. The socket is world-connectable, so the work is bounded:
at most 512 connections at once, five seconds for a client to send its
request and for nscd to answer, and a failed `accept()` is retried
rather than fatal.

## Running as the local DNS server

The third front-end sidesteps NSS altogether. With a `[dns_frontend]`
section the daemon serves DNS on a loopback address, over UDP and TCP;
point `/etc/resolv.conf` at it and every resolver on the machine goes
through the policy, glibc's `dns` source and programs with their own DNS
client (browsers, Go binaries) alike:

```toml
[dns_frontend]
listen = "127.0.0.1:53"
upstream = "192.0.2.53:53"   # the real resolver
upstream_timeout_ms = 5000   # optional
```

A DNS query carries no credentials, so the caller is read off the socket
it came from: `/proc/net/udp`, `/proc/net/udp6`, `/proc/net/tcp` and
`/proc/net/tcp6` list every local socket with its owner's uid and its
inode, readable by anyone. The socket is matched on the whole
connection (the client's address and port and the server address it
sent to), both tables are searched whatever the client's address family
(a dual-stack IPv6 socket talking to an IPv4 listener appears in the
IPv6 table with an IPv4-mapped address), and when sockets of different
users fit equally well nobody is identified. Turning the inode into a
process, and so into
a `gid` and `pid`, means finding it under `/proc/<pid>/fd`. For another
user's process that takes two capabilities: `CAP_DAC_READ_SEARCH` to
list the fd directory (it is mode 0500 and owned by that user) and
`CAP_SYS_PTRACE` to follow its links, the same reason `ss -p` wants
root. Without them the daemon says so once at startup and rules see
`gid == -1` and `pid == -1`. `uid` is `-1` only when no local socket
matches the query, which does not happen for queries from this machine.

Denied names get NXDOMAIN, the daemon's own records are answered
directly, and everything else is forwarded verbatim to the upstream
server over the transport the client used; an upstream that does not
answer within the timeout yields SERVFAIL. Only the question section is
interpreted, so every record type and EDNS pass through untouched; a
query for the root is judged like any other, under the name `"."`. The
listeners are world-reachable, so the work is bounded: at most 512 TCP
connections and in-flight UDP queries at once, five seconds for a TCP
client to send its query, and a failed `accept()` is retried rather
than fatal.

This mode does not combine with systemd-resolved: its stub resolver
would sit between the applications and the daemon, so every query
would identify `systemd-resolved` rather than the program that asked,
and its cache would be shared across users. The NixOS module refuses
that combination.

## Compile-time options

| Environment variable | Default                    | Purpose          |
| -------------------- | -------------------------- | ---------------- |
| `DEEZNS_SOCKET_PATH` | `/run/deezns/resolve.sock` | Unix socket path |

Set at build time: `DEEZNS_SOCKET_PATH=/my/path cargo build`

The socket path is a compile-time option rather than a runtime one
because of the NSS module. glibc loads `libnss_deezns.so.2` into
whatever process happens to call `getaddrinfo()` and gives it nothing
but the name to look up: NSS has no configuration mechanism of its own
(`/etc/nsswitch.conf` only names the modules and their actions), the
module cannot take command-line arguments, and it cannot rely on
environment variables, which are unset for setuid programs and system
services and would differ from process to process anyway. So the path
has to live inside the shared object itself. `build.rs` bakes the same
value into the daemon so the two sides can never disagree; moving the
socket means rebuilding both.

## Future directions

- **Live blocklist reload** via `SIGHUP` or inotify.
- **Upstream resolution** via hickory-dns instead of the stub.
- **AdBlock exception rules** (`@@||...^`) at the blocklist layer.
- **Supplementary groups** check via `/proc/<pid>/status` for richer
  GID-based policy.
- **Metrics** (Prometheus) for deny/allow/passthrough counters per UID.
