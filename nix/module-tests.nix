# Evaluation-time tests of the NixOS module's assertions: each configuration
# below must be accepted, or refused with an assertion that names the
# problem.  Building the derivation forces the evaluation; nothing is built
# beyond a file listing the outcomes.
{
  lib,
  pkgs,
  runCommand,
}: let
  evaluate = modules:
    (import "${pkgs.path}/nixos/lib/eval-config.nix" {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules =
        [
          ./module.nix
          {
            nixpkgs.pkgs = pkgs;
            system.stateVersion = lib.trivial.release;
          }
        ]
        ++ modules;
    }).config;

  # The module's own failing assertions (NixOS has others, about file
  # systems and boot loaders, that an unfinished configuration trips).
  refusals = modules:
    map (a: a.message) (lib.filter (a: !a.assertion && lib.hasInfix "deezns" a.message) (evaluate modules).assertions);

  accepts = name: modules: let
    messages = refusals modules;
  in
    if messages == []
    then "accepted: ${name}"
    else throw "${name}: expected to be accepted, but: ${lib.concatStringsSep " | " messages}";

  refuses = name: needle: modules: let
    messages = refusals modules;
  in
    if lib.any (lib.hasInfix needle) messages
    then "refused: ${name}"
    else throw "${name}: expected an assertion mentioning ${lib.strings.escapeNixString needle}, got: ${lib.concatStringsSep " | " messages}";

  dns = {
    services.deezns = {
      enable = true;
      frontend = "dns";
      dns.upstream = "192.0.2.53:53";
    };
  };

  results = [
    (accepts "nscd front-end with defaults" [{services.deezns.enable = true;}])
    (accepts "nss front-end" [
      {
        services.deezns = {
          enable = true;
          frontend = "nss";
        };
      }
    ])
    (accepts "dns front-end" [dns])
    (accepts "dns front-end identifying processes" [dns {services.deezns.dns.identifyProcesses = true;}])

    (refuses "nsncd's socket forced onto the daemon's nscd socket" "fight over it" [
      {
        services.deezns.enable = true;
        systemd.services.nscd.environment.NSNCD_SOCKET_PATH = lib.mkForce "/run/nscd/socket";
      }
    ])
    (refuses "nsncd's socket forced onto the daemon's policy socket" "fight over it" [
      {
        services.deezns.enable = true;
        systemd.services.nscd.environment.NSNCD_SOCKET_PATH = lib.mkForce "/run/deezns/resolve.sock";
      }
    ])
    (refuses "nsncd's socket moved behind the module's back" "differs from" [
      {
        services.deezns.enable = true;
        systemd.services.nscd.environment.NSNCD_SOCKET_PATH = lib.mkForce "/run/elsewhere/socket";
      }
    ])
    (refuses "the same path for two sockets" "three different paths" [
      {
        services.deezns = {
          enable = true;
          nscd.nsncdSocketPath = "/run/nscd/socket";
        };
      }
    ])
    (refuses "a socket outside /run" "under /run" [
      {
        services.deezns = {
          enable = true;
          nscd.nsncdSocketPath = "/var/run/nsncd/socket";
        };
      }
    ])
    (refuses "glibc's own nscd" "needs nsncd" [
      {
        services.deezns.enable = true;
        services.nscd.enableNsncd = false;
      }
    ])
    (refuses "no nscd at all" "services.nscd.enable" [
      {
        services.deezns.enable = true;
        services.nscd.enable = false;
        system.nssModules = lib.mkForce [];
      }
    ])
    (refuses "dns front-end without an upstream" "dns.upstream" [
      {
        services.deezns = {
          enable = true;
          frontend = "dns";
        };
      }
    ])
    (refuses "dns front-end with a malformed listen address" "address:port" [dns {services.deezns.dns.listen = "nonsense";}])
    (refuses "dns front-end with systemd-resolved" "systemd-resolved" [dns {services.resolved.enable = true;}])
  ];
in
  runCommand "deezns-module-assertions" {results = lib.concatStringsSep "\n" results;} ''
    printf '%s\n' "$results" > "$out"
  ''
