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
    flake-parts.lib.mkFlake {inherit inputs;} {
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

      perSystem = {
        config,
        pkgs,
        ...
      }: {
        packages = {
          deezns = pkgs.callPackage ./nix/package.nix {};
          default = config.packages.deezns;
        };

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
          # Documentation
          programs.prettier.enable = true;
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
    };
}
