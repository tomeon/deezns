# Evaluation-time tests of the NixOS module's assertions: each configuration
# below must be accepted, or refused with an assertion that names the
# problem, and a few must produce particular settings.  Building the
# derivation forces the evaluation; nothing is built beyond a file listing
# the outcomes.
{localFlake}: {
  lib,
  pkgs,
  runCommand,
}: let
  evaluate = modules:
    (import "${pkgs.path}/nixos/lib/eval-config.nix" {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules =
        [
          localFlake.nixosModules.deezns
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

  # `check` holds for the evaluated configuration.
  yields = name: check: modules:
    if check (evaluate modules)
    then "holds: ${name}"
    else throw "${name}: the configuration does not have the expected settings";

  # The front-ends, enabled as given.
  frontends = {
    nscd ? false,
    dns ? false,
    nss ? false,
  }: {
    services.deezns = {
      enable = true;
      settings = {
        nscd_frontend.enable = nscd;
        dns_frontend = {
          enable = dns;
          upstream = "192.0.2.53:53";
        };
        nss_frontend.enable = nss;
      };
    };
  };

  dns = frontends {dns = true;};

  # Every subset of the three front-ends, the empty one included.
  combinations = lib.cartesianProduct {
    nscd = [false true];
    dns = [false true];
    nss = [false true];
  };

  describe = enabled: let
    names = lib.attrNames (lib.filterAttrs (_: on: on) enabled);
  in
    if names == []
    then "no front-end"
    else "front-ends: ${lib.concatStringsSep " + " names}";

  ignoresHosts = config: config.systemd.services.nscd.environment ? NSNCD_IGNORE_HOSTS;
  capabilities = config: config.systemd.services.deezns.serviceConfig.AmbientCapabilities;

  results =
    [
      (accepts "nscd front-end with defaults" [{services.deezns.enable = true;}])
      (accepts "dns front-end identifying processes" [dns {services.deezns.settings.dns_frontend.identify_processes = true;}])
      (accepts "no front-end and no nscd" [
        (frontends {})
        {
          services.nscd.enable = false;
          system.nssModules = lib.mkForce [];
        }
      ])
      (accepts "NSS module after dns, behind the nscd front-end" [
        (frontends {
          nscd = true;
          dns = true;
          nss = true;
        })
        {services.deezns.nssOrder = 1600;}
      ])
    ]
    ++ map (enabled: accepts (describe enabled) [(frontends enabled)]) combinations
    ++ [
      (yields "only the nscd front-end is on by default" (
          c: let
            s = c.services.deezns.settings;
          in
            s.nscd_frontend.enable && !s.dns_frontend.enable && !s.nss_frontend.enable
        ) [
          {services.deezns.enable = true;}
        ])
      (yields "the daemon knows nsncd's user" (c: c.services.deezns.settings.nscd_user == c.services.nscd.user) [
        {services.deezns.enable = true;}
      ])
      (yields "the DNS front-end alone leaves host lookups to glibc" ignoresHosts [dns])
      (yields "the DNS front-end with the nscd front-end keeps nsncd resolving hosts" (c: !ignoresHosts c) [
        (frontends {
          nscd = true;
          dns = true;
        })
      ])
      (yields "the DNS front-end with the NSS module keeps nsncd resolving hosts" (c: !ignoresHosts c) [
        (frontends {
          dns = true;
          nss = true;
        })
      ])
      (yields "identify_processes grants the capabilities it needs" (c: lib.hasInfix "CAP_SYS_PTRACE" (capabilities c)) [
        dns
        {services.deezns.settings.dns_frontend.identify_processes = true;}
      ])
      (yields "without identify_processes the daemon keeps only CAP_NET_BIND_SERVICE" (c: capabilities c == "CAP_NET_BIND_SERVICE") [dns])

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
            settings.nscd_frontend.upstream = "/run/nscd/socket";
          };
        }
      ])
      (refuses "a socket outside /run" "under /run" [
        {
          services.deezns = {
            enable = true;
            settings.nscd_frontend.upstream = "/var/run/nsncd/socket";
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
      (refuses "dns front-end without an upstream" "needs an upstream" [
        {
          services.deezns = {
            enable = true;
            settings.dns_frontend.enable = true;
          };
        }
      ])
      (refuses "dns front-end with glibc's own nscd" "needs nsncd" [
        dns
        {services.nscd.enableNsncd = false;}
      ])
      (refuses "NSS module after dns in front of the DNS front-end" "must be below" [
        (frontends {
          dns = true;
          nss = true;
        })
        {services.deezns.nssOrder = 1600;}
      ])
      (refuses "dns front-end with a malformed listen address" "address:port" [dns {services.deezns.settings.dns_frontend.listen = "nonsense";}])
      (refuses "dns front-end with systemd-resolved" "systemd-resolved" [dns {services.resolved.enable = true;}])
    ];
in
  runCommand "deezns-module-assertions" {results = lib.concatStringsSep "\n" results;} ''
    printf '%s\n' "$results" > "$out"
  ''
