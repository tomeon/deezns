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
      nscd.enable = nscd;
      dns = {
        enable = dns;
        upstream = "192.0.2.53:53";
      };
      nss.enable = nss;
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

  results =
    [
      (accepts "nscd front-end with defaults" [{services.deezns.enable = true;}])
      (accepts "dns front-end identifying processes" [dns {services.deezns.dns.identifyProcesses = true;}])
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
        {services.deezns.nss.order = 1600;}
      ])
    ]
    ++ map (enabled: accepts (describe enabled) [(frontends enabled)]) combinations
    ++ [
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
      (yields "the DNS front-end alone relays nobody" (c: c.services.deezns.settings.dns_frontend.relay_users == []) [dns])
      (yields "behind the nscd front-end, nsncd is a relay on both other listeners" (
          c:
            c.services.deezns.settings.dns_frontend.relay_users
            == ["nscd"]
            && c.services.deezns.settings.policy_socket.relay_users == ["nscd"]
        ) [
          (frontends {
            nscd = true;
            dns = true;
            nss = true;
          })
        ])
      (yields "behind the NSS module alone, nsncd is a relay on the DNS front-end only" (
          c:
            c.services.deezns.settings.dns_frontend.relay_users
            == ["nscd"]
            && c.services.deezns.settings.policy_socket.relay_users == []
        ) [
          (frontends {
            dns = true;
            nss = true;
          })
        ])
      (yields "nssOrder is renamed to nss.order" (c: c.services.deezns.nss.order == 1200) [
        (frontends {nss = true;})
        {services.deezns.nssOrder = 1200;}
      ])
      (yields "the nscd front-end is on by default" (c: c.services.deezns.nscd.enable && !c.services.deezns.dns.enable && !c.services.deezns.nss.enable) [
        {services.deezns.enable = true;}
      ])

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
            dns.enable = true;
          };
        }
      ])
      (refuses "dns front-end with glibc's own nscd" "needs nsncd" [
        dns
        {services.nscd.enableNsncd = false;}
      ])
      (refuses "NSS module after dns in front of the DNS front-end" "must be" [
        (frontends {
          dns = true;
          nss = true;
        })
        {services.deezns.nss.order = 1600;}
      ])
      (refuses "the removed frontend option" "no longer has any effect" [
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
