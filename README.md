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
for its next hundred lookups), an unreachable nscd yields a temporary
failure for host lookups, and other requests fall back to glibc's
built-in sources. Reverse lookups carry an address rather than a name
and are forwarded unfiltered.

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
