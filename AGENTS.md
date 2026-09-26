# Guidelines for agents working on this repository

This is deezns: a per-UID DNS policy daemon (`deezns-daemon`, a tokio
program listening on a Unix socket and evaluating CEL rules) and the
glibc NSS module (`libnss_deezns.so.2`) that consults it. The Rust
sources live in `src/`, `build.rs`, `Cargo.toml` and `Cargo.lock`, with
an example policy in `config/`. Everything Nix-related was added on
top: `flake.nix`, `flake.lock`, `nix/`, `scripts/`, `.github/`.

## Flake layout

- `flake.nix` uses flake-parts, the numtide devshell flake module, and
  the treefmt-nix flake module. Supported systems: x86_64-linux and
  aarch64-linux only; an NSS module is glibc-specific, and the daemon
  relies on `SO_PEERCRED`, so there is nothing to build for Darwin.
- `packages.deezns` is `nix/package.nix` called with `pkgs.callPackage`:
  `rustPlatform.buildRustPackage` with `cargoLock.lockFile = ../Cargo.lock`
  (no `cargoHash` to maintain; dependencies come straight from the
  lock file). `packages.default` is the same derivation.
  - `src` is a fileset of just `Cargo.toml`, `Cargo.lock`, `build.rs`
    and `src/`, so editing the Nix files, the docs or the example policy
    does not rebuild the package. The fileset only contains git-tracked
    files, so `git add` new sources before `nix build` or they are
    missing from the build.
  - `pname` and `version` are read from `Cargo.toml`
    (`lib.importTOML`); bump the version there, nowhere else.
  - The socket path is a package argument (`socketPath`, default
    `/run/deezns/resolve.sock`) exported as `DEEZNS_SOCKET_PATH`, which
    `build.rs` bakes into both the daemon and the NSS module. It has to
    be a compile-time option: glibc loads the NSS module into arbitrary
    processes with no configuration channel (nsswitch.conf carries no
    settings, and environment variables are unreliable there), so the
    path must be inside the shared object, and the daemon is built with
    the same value to stay consistent.
  - `postInstall` renames cargo's `libnss_deezns.so` to
    `libnss_deezns.so.2` (the name glibc looks up) and sets its SONAME
    to match; the example policy is installed under `share/doc/deezns/`.
  - `passthru.socketPath` exposes the compiled-in socket path; the
    NixOS module reads it from there.
  - The toolchain is nixpkgs' stable Rust (`rustc`, `cargo`, `clippy`,
    `rustfmt`, `rust-analyzer`). No third-party Rust flake
    (rust-overlay, fenix, crane) is used: the crate is edition 2021 with
    no `rust-toolchain` file and no nightly features, so nixpkgs' stable
    toolchain builds it and adding an input would only add a second
    Rust to keep in sync. Reach for rust-overlay or fenix only if the
    project grows a real need for a pinned or nightly toolchain.
- `nixosModules.deezns` (also `nixosModules.default`) is
  `nix/module.nix`: `services.deezns.{enable,package,frontend,settings}`
  plus a read-only `socketPath` taken from the package's
  `passthru.socketPath`. Daemon settings are declared once, as options
  under `settings` (e.g. `settings.nscd_frontend.{listen,upstream}`,
  `settings.dns_frontend.{listen,upstream}`), and the rest of the module
  reads them from there; the module never assigns to `settings` itself.
  Only the selected front-end's section is written to the policy file.
  Top-level options are kept for what is not daemon configuration
  (`frontend`, `dns.identifyProcesses`, `nssOrder`). The daemon runs as user `deezns` under a
  hardened systemd unit. `frontend` picks how glibc's lookups reach it:
  - `nscd` (default): the daemon answers on
    `settings.nscd_frontend.listen` (`/run/nscd/socket`) in nscd's place (`src/nscd.rs`, glibc's nscd protocol) and nsncd is
    moved to `settings.nscd_frontend.upstream` (`/run/nsncd/socket`) via
    `NSNCD_SOCKET_PATH`, with its
    RuntimeDirectory forced to match. Host lookups are judged with the
    real caller's `SO_PEERCRED`; every other request is forwarded to
    nsncd byte for byte. Assertions require nsncd, keep the three socket
    paths distinct, and check nscd.service's effective
    `NSNCD_SOCKET_PATH`. A denial must be answered as `found=0` with
    `HOST_NOT_FOUND`: `found=-1` or a closed connection makes glibc
    bypass nscd for its next hundred lookups.
  - `dns`: the daemon serves DNS on `settings.dns_frontend.listen`
    (`src/dns.rs`, UDP and TCP, forwarding to `settings.dns_frontend.upstream`), is put
    first in `networking.nameservers`, and nscd.service gets
    `NSNCD_IGNORE_HOSTS=true` so glibc resolves in-process and the query
    leaves the caller's own socket. `src/identify.rs` reads the caller's
    uid from `/proc/net/{udp,udp6,tcp,tcp6}`; with
    `dns.identifyProcesses` (off by default) the unit gets
    `CAP_DAC_READ_SEARCH` (to list another user's 0500 `/proc/<pid>/fd`)
    and `CAP_SYS_PTRACE` (to follow its links) and the pid and gid are
    found via `/proc/<pid>/fd` and status, otherwise rules see
    `gid == -1` and `pid == -1`. The
    unit also gets `CAP_NET_BIND_SERVICE`, `AF_INET`/`AF_INET6` and
    `ProcSubset=all` (for `/proc/net`). This mode also covers programs
    with their own DNS client, and refuses systemd-resolved, whose stub
    would hide the caller. Sockets are matched on the whole connection
    across both address families' tables; sockets of different users
    that fit equally well identify nobody.
  - Names are canonicalised (lower-case, no trailing dot; the root is
    `"."`) before rules and blocklists see them. Both listeners bound
    their work (512 connections, 5 s deadlines) and the nscd front-end
    validates the real nscd's host replies before relaying them, since
    an empty or `found=-1` reply makes glibc bypass nscd.
  - `nss`: the package goes into `system.nssModules` and
    `deezns [!UNAVAIL=return]` into the `hosts` line at `nssOrder`.
    NixOS loads third-party NSS modules only inside nsncd, so the
    daemon then sees nsncd's uid, gid and pid for every lookup made
    through glibc; the nscd user joins group `deezns` to reach the 0660
    socket. `[!UNAVAIL=return]` makes every status except UNAVAIL
    final; glibc's default is `SUCCESS=return` and `continue` for the
    rest, so without it a denial would fall through to `dns`.
- `packages.nsncd` is nixpkgs' nsncd with `nix/nsncd-peer-cred.patch`, an
  earlier prototype for the same problem: nsncd records each client's
  `SO_PEERCRED` in a thread-local while handling its request and
  exports it from the binary as `nsncd_peer_cred()`, which an NSS
  module can find with `dlsym(RTLD_DEFAULT, ...)` on the thread doing
  the lookup. The nscd front-end made it unnecessary; it is kept as a
  reference. The patch is a git format-patch against nsncd v1.5.2 and
  carries its own unit tests, which `nix build .#nsncd` runs.
- `checks.<system>.module-assertions` is `nix/module-tests.nix`: it
  evaluates the module against configurations that must be accepted or
  refused (socket-path collisions, glibc's nscd, a missing DNS upstream,
  systemd-resolved with the dns front-end) and fails the evaluation
  otherwise. Add a case there whenever the module gains an assertion.
- `checks.<system>.treefmt` comes from treefmt-nix; `nix flake check`
  also builds the packages and the devshell.
- `checks.<system>.nixos-test` is `pkgs.testers.runNixOSTest ./nix/test.nix`:
  a `resolver` VM running dnsmasq for a set of test names and a `client`
  VM running the module. The script looks every name up both directly
  against the resolver (`dig`) and through glibc (`getent ahosts`, also
  as different users via `runuser`), and checks the daemon's verdicts
  over its socket. Specialisations switch the client to a default-deny
  policy and to the other front-ends mid-test; they are reached through
  the base system's store path, since `/run/current-system` moves. See
  "NixOS test" below for running it in the sandbox.
- The devshell (`nix develop`, `menu`) provides the Rust toolchain, the
  treefmt wrapper, git, python3 and `flake-inputs-via-git` as a command.
- `.github/workflows/checks.yml` runs `nix flake check -L` on every
  push, pull request and manual dispatch, with the Nix store cached
  between runs keyed on `flake.lock`. A udev rule opens `/dev/kvm` to
  everyone first, since the VM test needs it inside the build sandbox.

## Conventions

- Run `nix fmt` after every change and fix anything a formatter reports
  but cannot fix itself. treefmt runs rustfmt (edition taken from
  `Cargo.toml`), taplo (TOML), alejandra, deadnix and statix (Nix),
  prettier (Markdown and other documentation, plus the workflow YAML),
  actionlint (GitHub Actions workflows), and ruff-check and ruff-format
  (the listed Python scripts).
- The scripts in `scripts/` have no file extensions, so every new
  Python script must be added to the `ruff-check` and `ruff-format`
  `includes` lists in `flake.nix`.
- Prefer an existing library function over hand-rolled code.
- Every task ends with the relevant success commands exiting 0, and
  with the work committed and pushed to the designated branch.

## Verification commands

All of these must exit 0:

```
nix flake show
nix develop -c menu
nix fmt
nix build .#deezns
nix build .#            # same output path as .#deezns
nix flake check
cargo test              # inside `nix develop`; also run by nix build
```

A `nix build` from scratch compiles the crate and its ~90 dependencies,
a few minutes on a laptop. Run it detached and follow the log rather
than waiting on a foreground command with a timeout.

### NixOS test

`nix flake check` includes the VM test, whose derivation requires the
`kvm` system feature. The development sandbox has no `/dev/kvm`, so Nix
does not advertise the feature and refuses to build it; passing the
feature explicitly makes Nix accept the derivation, and QEMU
(`-machine accel=kvm:tcg`) falls back to software emulation:

```
nix flake check -L --option system-features "nixos-test benchmark big-parallel kvm"
nix build -L --option system-features "nixos-test benchmark big-parallel kvm" .#checks.x86_64-linux.nixos-test
```

Emulated, the two VMs take on the order of ten minutes; run it
detached. The test can also be driven interactively with
`nix build .#checks.x86_64-linux.nixos-test.driverInteractive` and
`result/bin/nixos-test-driver`. On a machine with KVM the plain
commands work.

## Helper scripts (`scripts/`, also devshell commands)

They exist because the development sandbox has these restrictions; each
one degrades to the plain command on an ordinary machine.

| Restriction                                                                                                                                                                           | Tool                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| GitHub's API and tarball endpoints return 403 for repositories outside the session, while anonymous `git` access works; so `github:` flake inputs cannot be fetched or updated by Nix | `scripts/flake-inputs-via-git` (fetches locked inputs over git; `--update` replaces `nix flake update`) |

Other facts about the sandbox worth knowing before trying something:

- Nix is installed but not on `PATH`; it lives in
  `/nix/var/nix/profiles/default/bin`.
- Nix runs in single-user mode as root. `--option` settings on the
  command line are honoured.
- `cache.nixos.org` and `crates.io` are reachable, so substitutes and
  the cargo vendor derivations download normally; only GitHub's API is
  blocked.
- The proxy's port changes between sessions; always read it from the
  environment (`HTTPS_PROXY`).

## Communication

- Be polite but not fawning; get to the point.
- Do not put words in the user's mouth. When something they said
  seems wrong, consider first that the misunderstanding may be yours.
- Apply the principle of charity; pick no nits.
- Provide citations and links for sources.
