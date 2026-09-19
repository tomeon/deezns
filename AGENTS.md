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
    `build.rs` bakes into both the daemon and the NSS module.
  - `postInstall` renames cargo's `libnss_deezns.so` to
    `libnss_deezns.so.2` (the name glibc looks up) and sets its SONAME
    to match; the example policy is installed under `share/doc/deezns/`.
  - The toolchain is nixpkgs' stable Rust (`rustc`, `cargo`, `clippy`,
    `rustfmt`, `rust-analyzer`). No third-party Rust flake
    (rust-overlay, fenix, crane) is used: the crate is edition 2021 with
    no `rust-toolchain` file and no nightly features, so nixpkgs' stable
    toolchain builds it and adding an input would only add a second
    Rust to keep in sync. Reach for rust-overlay or fenix only if the
    project grows a real need for a pinned or nightly toolchain.
- `checks.<system>.treefmt` comes from treefmt-nix; `nix flake check`
  also builds the packages and the devshell.
- The devshell (`nix develop`, `menu`) provides the Rust toolchain, the
  treefmt wrapper, git, python3 and `flake-inputs-via-git` as a command.
- `.github/workflows/checks.yml` runs `nix flake check -L` on every
  push, pull request and manual dispatch, with the Nix store cached
  between runs keyed on `flake.lock`.

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
