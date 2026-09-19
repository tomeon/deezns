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

| Variable   | Type   | Description                      |
|------------|--------|----------------------------------|
| `hostname` | string | Queried hostname (lowercased)    |
| `uid`      | int    | Peer UID from SO_PEERCRED        |
| `gid`      | int    | Peer GID                         |
| `pid`      | int    | Peer PID                         |

### CEL functions

| Function                   | Returns | Description                                |
|----------------------------|---------|--------------------------------------------|
| `blocked_by("list_name")`  | bool    | True if hostname is in the named blocklist |

Plus all built-in CEL string methods: `endsWith`, `startsWith`, `contains`,
`matches` (regex, requires the `regex` feature on `cel-interpreter`).

### Verdicts

| Verdict       | NSS behaviour                                        |
|---------------|------------------------------------------------------|
| `deny`        | NXDOMAIN — stops the NSS chain                       |
| `passthrough` | Return UNAVAIL — glibc tries the next source         |
| `allow`       | Proceed with upstream resolution                     |

Rules are evaluated in order; **first match wins**.

### Blocklist formats

The blocklist loader (`src/blocklist.rs`) auto-detects three formats:

- **Hosts-file**: `127.0.0.1 ad.example.com` (exact match)
- **Domains-only**: `ad.example.com` (exact match)
- **AdBlock-style**: `||example.com^` (domain + all subdomains)

This means you can point it at lists from StevenBlack/hosts, oisd, or any
AdGuard/uBlock-compatible domain blocklist.  AdBlock exception rules
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

## Compile-time options

| Environment variable   | Default                    | Purpose               |
|------------------------|----------------------------|-----------------------|
| `DEEZNS_SOCKET_PATH`   | `/run/deezns/resolve.sock` | Unix socket path      |

Set at build time: `DEEZNS_SOCKET_PATH=/my/path cargo build`

## Future directions

- **Live blocklist reload** via `SIGHUP` or inotify.
- **Upstream resolution** via hickory-dns instead of the stub.
- **AdBlock exception rules** (`@@||...^`) at the blocklist layer.
- **Supplementary groups** check via `/proc/<pid>/status` for richer
  GID-based policy.
- **Metrics** (Prometheus) for deny/allow/passthrough counters per UID.
