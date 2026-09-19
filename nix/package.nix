# The deezns daemon and NSS module, built from this checkout with nixpkgs'
# Rust toolchain.  `pkgs.callPackage ./nix/package.nix { socketPath = ...; }`
# rebuilds it for another socket location.
{
  lib,
  rustPlatform,
  # The Unix socket the NSS module and the daemon talk over.  build.rs bakes
  # it into both at compile time (see "Compile-time options" in README.md):
  # glibc gives an NSS module no way to read configuration, so the path must
  # be inside libnss_deezns.so.2 itself, and the daemon is compiled with the
  # same value so the two cannot disagree.
  socketPath ? "/run/deezns/resolve.sock",
}: let
  cargoToml = lib.importTOML ../Cargo.toml;
in
  rustPlatform.buildRustPackage {
    pname = cargoToml.package.name;
    inherit (cargoToml.package) version;

    # Only what cargo needs: editing the Nix files, the docs or the example
    # policy does not rebuild the package.
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../Cargo.toml
        ../Cargo.lock
        ../build.rs
        ../src
      ];
    };

    cargoLock.lockFile = ../Cargo.lock;

    env.DEEZNS_SOCKET_PATH = socketPath;

    postInstall = ''
      # glibc looks NSS modules up as libnss_<service>.so.2; cargo names the
      # cdylib libnss_deezns.so.
      mv "$out/lib/libnss_deezns.so" "$out/lib/libnss_deezns.so.2"
      patchelf --set-soname libnss_deezns.so.2 "$out/lib/libnss_deezns.so.2"

      install -Dm644 ${../config/policy.toml} "$out/share/doc/deezns/policy.toml"
    '';

    meta = {
      description = "Per-UID DNS policy daemon with CEL rules and blocklist support";
      homepage = "https://github.com/tomeon/deezns";
      # An NSS module only makes sense against glibc.
      platforms = lib.platforms.linux;
      mainProgram = "deezns-daemon";
    };
  }
