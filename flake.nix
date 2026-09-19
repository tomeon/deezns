{
  description = "deezns: per-UID DNS policy daemon with CEL rules and blocklist support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };

    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} ({config, ...}: {
      imports = [
        inputs.devshell.flakeModule
        inputs.treefmt-nix.flakeModule
      ];

      # deezns is a glibc NSS module plus a daemon speaking SO_PEERCRED over
      # a Unix socket, so it is Linux-only.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      flake.nixosModules = {
        deezns.imports = [./nix/module.nix];
        default = config.flake.nixosModules.deezns;
      };

      perSystem = {
        config,
        pkgs,
        ...
      }: {
        packages = {
          deezns = pkgs.callPackage ./nix/package.nix {};
          default = config.packages.deezns;

          # nixpkgs' nsncd with a prototype patch that lets NSS modules loaded
          # into it learn the credentials of the process whose lookup they
          # are serving (see the patch header).  Not used by the NixOS module
          # yet.
          nsncd = pkgs.nsncd.overrideAttrs (previous: {
            patches = (previous.patches or []) ++ [./nix/nsncd-peer-cred.patch];
          });
        };

        # The VM test boots two machines (a resolver and a deezns client),
        # so it needs KVM, or a builder that declares the `kvm` feature and
        # lets QEMU fall back to emulation.  See "NixOS test" in AGENTS.md.
        checks.nixos-test = pkgs.testers.runNixOSTest ./nix/test.nix;

        treefmt = {
          projectRootFile = "flake.nix";

          # Rust
          programs.rustfmt = {
            enable = true;
            edition = (pkgs.lib.importTOML ./Cargo.toml).package.edition;
          };
          # TOML: Cargo.toml and the policy files
          programs.taplo.enable = true;
          # Nix
          programs.alejandra.enable = true;
          programs.deadnix.enable = true;
          programs.statix.enable = true;
          # Documentation (and the workflow YAML)
          programs.prettier.enable = true;
          # GitHub Actions workflows
          programs.actionlint.enable = true;
          # Python written for this flake.  The scripts have no file
          # extensions, so list them.
          programs.ruff-check = {
            enable = true;
            includes = ["scripts/flake-inputs-via-git"];
          };
          programs.ruff-format = {
            enable = true;
            includes = ["scripts/flake-inputs-via-git"];
          };
        };

        devshells.default = {
          packages = [
            config.treefmt.build.wrapper
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rust-analyzer
            pkgs.rustfmt
            pkgs.git
            pkgs.python3
          ];
          commands = [
            {
              name = "flake-inputs-via-git";
              help = "fetch or update github: flake inputs over git, without the GitHub API";
              category = "sandbox helpers";
              command = ''exec "$PRJ_ROOT/scripts/flake-inputs-via-git" "$@"'';
            }
          ];
        };
      };
    });
}
