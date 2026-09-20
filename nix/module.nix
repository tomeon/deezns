# NixOS module for deezns: runs the daemon as a hardened systemd service and
# plugs it into the system's name resolution in one of two ways.
#
# How NSS works on NixOS matters here.  Third-party NSS modules are not
# loadable by arbitrary processes (glibc searches only its own lib directory
# and LD_LIBRARY_PATH); NixOS instead lists them in `system.nssModules` and
# points nscd (nsncd by default) at them, and every process' lookups go
# through nscd's socket.  The module therefore offers two front-ends:
#
#   * `frontend = "nscd"` (the default): the daemon itself answers on
#     nscd's socket, /run/nscd/socket, and nsncd is moved to another path
#     behind it.  Host lookups are judged with the credentials of the
#     process that asked; everything else is forwarded to nsncd unchanged.
#     The NSS module is not used.
#
#   * `frontend = "nss"`: the classic arrangement, libnss_deezns.so.2 in
#     nsswitch.conf.  On NixOS it runs inside nsncd, so `uid`, `gid` and
#     `pid` carry nsncd's credentials for every lookup made through glibc;
#     hostname and blocklist rules work as documented.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.deezns;

  settingsFormat = pkgs.formats.toml {};
  # TOML has no null; an unset optional section is simply left out.
  policyFile = settingsFormat.generate "deezns-policy.toml" (lib.filterAttrs (_: v: v != null) cfg.settings);

  # The name of a directory under /run, for RuntimeDirectory=.
  runtimeDirectoryOf = path: lib.removePrefix "/run/" (dirOf path);

  nscdFrontend = cfg.frontend == "nscd";
  nssFrontend = cfg.frontend == "nss";

  nscdEnvironment = config.systemd.services.nscd.environment;
  effectiveNsncdSocket = nscdEnvironment.NSNCD_SOCKET_PATH or null;
in {
  options.services.deezns = {
    enable = lib.mkEnableOption "deezns, a DNS policy daemon consulted by glibc through nscd or an NSS module";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix {};
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = ''
        The deezns package, providing both `bin/deezns-daemon` and the NSS
        module `lib/libnss_deezns.so.2`.

        The path of the Unix socket the two talk over is not a runtime
        setting: glibc offers an NSS module no way to read configuration, so
        `build.rs` compiles the path into the shared object, and into the
        daemon so that both agree.  Using a socket path other than the
        default `/run/deezns/resolve.sock` therefore means rebuilding the
        package with the `socketPath` argument, for example

        ```nix
        services.deezns.package = pkgs.callPackage "''${deezns}/nix/package.nix" {
          socketPath = "/run/deezns-alt/resolve.sock";
        };
        ```

        or, starting from the flake's package,

        ```nix
        services.deezns.package = deezns.packages.''${pkgs.stdenv.hostPlatform.system}.deezns.override {
          socketPath = "/run/deezns-alt/resolve.sock";
        };
        ```

        The module reads the socket path back from the package's
        `passthru.socketPath` (see {option}`services.deezns.socketPath`)
        and requires it to be under `/run`.
      '';
    };

    socketPath = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = cfg.package.socketPath or "/run/deezns/resolve.sock";
      defaultText = lib.literalExpression ''cfg.package.socketPath or "/run/deezns/resolve.sock"'';
      description = ''
        The Unix socket the daemon's own policy protocol listens on, as
        compiled into {option}`services.deezns.package`.  Read-only: to
        change it, rebuild the package (see the description of that option).
      '';
    };

    frontend = lib.mkOption {
      type = lib.types.enum ["nscd" "nss"];
      default = "nscd";
      description = ''
        How glibc's lookups reach the daemon.

        `nscd`: the daemon listens on nscd's socket
        ({option}`services.deezns.nscd.socketPath`) in place of nsncd,
        which is moved to {option}`services.deezns.nscd.nsncdSocketPath`.
        Host lookups are judged with the credentials of the process that
        asked; all other requests are forwarded to nsncd unchanged.
        Requires nsncd ({option}`services.nscd.enableNsncd`).

        `nss`: `libnss_deezns.so.2` is added to the `hosts` line of
        `/etc/nsswitch.conf`.  Because NixOS runs NSS modules inside
        nsncd, the daemon then sees nsncd's uid, gid and pid for every
        lookup made through glibc; only clients of the daemon's own socket
        are identified individually.
      '';
    };

    nscd = {
      socketPath = lib.mkOption {
        type = lib.types.path;
        default = "/run/nscd/socket";
        description = ''
          Where the daemon listens for glibc's nscd client when
          {option}`services.deezns.frontend` is `nscd`.  glibc has this
          path compiled in (`/var/run/nscd/socket`, and `/var/run` is
          `/run`), so there is normally no reason to change it.
        '';
      };

      nsncdSocketPath = lib.mkOption {
        type = lib.types.path;
        default = "/run/nsncd/socket";
        description = ''
          Where nsncd listens instead, and where the daemon forwards the
          requests it does not answer itself.  Set on `nscd.service` as
          `NSNCD_SOCKET_PATH`; must be under `/run` and differ from both
          {option}`services.deezns.nscd.socketPath` and
          {option}`services.deezns.socketPath`.
        '';
      };
    };

    nssOrder = lib.mkOption {
      type = lib.types.int;
      default =
        if config.services.resolved.enable
        then 500
        else 1000;
      defaultText = lib.literalExpression "if config.services.resolved.enable then 500 else 1000";
      description = ''
        With {option}`services.deezns.frontend` set to `nss`: the position
        of `deezns` in the `hosts` line of `/etc/nsswitch.conf`, as a
        `lib.mkOrder` priority.  NixOS places `mymachines` at 400,
        `resolve` at 501, `files` at 998, `myhostname` at 999 and `dns` at
        1499.

        The default puts deezns after `files` (so `/etc/hosts` entries are
        never subject to policy) and before `dns`.  With systemd-resolved
        enabled, `resolve` answers before `files` and stops the lookup, so
        deezns is moved ahead of it; names from `/etc/hosts` are then
        evaluated against the policy too.
      '';
    };

    settings = lib.mkOption {
      description = ''
        The daemon's policy, written to a TOML file that is passed to the
        daemon as `DEEZNS_CONFIG`.  See `config/policy.toml` in the deezns
        sources for a commented example and the README for the CEL
        variables and functions available to rules.
      '';
      default = {};
      type = lib.types.submodule {
        freeformType = settingsFormat.type;

        options = {
          default_verdict = lib.mkOption {
            type = lib.types.enum ["passthrough" "deny"];
            default = "passthrough";
            description = ''
              Verdict for lookups no rule matches: `passthrough` hands the
              name to the next resolver (normally `dns`); `deny` answers
              "no such host" for everything not explicitly allowed.
            '';
          };

          blocklists = lib.mkOption {
            default = [];
            description = ''
              Domain lists loaded when the daemon starts and exposed to
              rules as `blocked_by("<name>")`.  Hosts-file, domains-only
              and AdBlock (`||domain^`) formats are detected automatically.
            '';
            type = lib.types.listOf (lib.types.submodule {
              options = {
                name = lib.mkOption {
                  type = lib.types.str;
                  description = "Name the list is referred to by in `blocked_by(...)`.";
                };
                path = lib.mkOption {
                  type = lib.types.path;
                  description = ''
                    The list file.  A path literal or a derivation puts the
                    list in the Nix store; a string is read from the running
                    system at daemon start and must be readable by the
                    `deezns` user, which cannot see `/home`.
                  '';
                };
              };
            });
          };

          rules = lib.mkOption {
            default = [];
            description = "Rules, evaluated in order; the first whose expression is true decides.";
            type = lib.types.listOf (lib.types.submodule {
              options = {
                note = lib.mkOption {
                  type = lib.types.str;
                  default = "";
                  description = "Free-form label, shown in the daemon's log when the rule fires.";
                };
                expr = lib.mkOption {
                  type = lib.types.str;
                  description = ''
                    CEL expression over `hostname`, `uid`, `gid`, `pid` and
                    `blocked_by(name)`.  `gid` and `pid` are `-1` when a
                    front-end could not determine them.
                  '';
                };
                verdict = lib.mkOption {
                  type = lib.types.enum ["allow" "deny" "passthrough"];
                  description = "What to do when the expression is true.";
                };
              };
            });
          };

          nscd_frontend = lib.mkOption {
            default = null;
            description = ''
              The daemon's nscd-protocol front-end.  Set by the module from
              {option}`services.deezns.nscd` when
              {option}`services.deezns.frontend` is `nscd`.
            '';
            type = lib.types.nullOr (lib.types.submodule {
              options = {
                listen = lib.mkOption {
                  type = lib.types.path;
                  description = "The socket glibc's nscd client connects to.";
                };
                upstream = lib.mkOption {
                  type = lib.types.path;
                  description = "The real nscd that answers what deezns does not.";
                };
              };
            });
          };
        };
      };
      example = lib.literalExpression ''
        {
          default_verdict = "deny";
          blocklists = [
            { name = "ads"; path = "/var/lib/deezns/ads.txt"; }
          ];
          rules = [
            { note = "ads"; expr = "blocked_by(\"ads\")"; verdict = "deny"; }
            { note = "trusted sites"; expr = "hostname.endsWith(\".example.org\")"; verdict = "allow"; }
          ];
        }
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    # ── Common ────────────────────────────────────────────────────────
    {
      assertions = [
        {
          assertion = config.services.nscd.enable;
          message = ''
            services.deezns needs services.nscd.enable: NixOS routes name
            lookups through nscd, and both deezns front-ends build on that.
          '';
        }
        {
          assertion = lib.hasPrefix "/run/" cfg.socketPath;
          message = ''
            services.deezns: the socket path compiled into the package
            (${cfg.socketPath}) must be under /run, where the service's
            RuntimeDirectory is created.
          '';
        }
      ];

      # The daemon runs as its own user; the socket it creates is 0660, so
      # anything that should be able to query it directly needs group
      # `deezns`.
      users.users.deezns = {
        isSystemUser = true;
        group = "deezns";
        description = "deezns DNS policy daemon";
      };
      users.groups.deezns = {};

      systemd.services.deezns = {
        description = "deezns DNS policy daemon";
        documentation = ["https://github.com/tomeon/deezns"];
        wantedBy = ["multi-user.target"];
        # Be up before anything that needs name resolution, nscd included:
        # while the daemon is down, lookups go straight to `dns`, unfiltered.
        before = ["nss-lookup.target" "nscd.service"];
        wants = ["nss-lookup.target"];

        environment = {
          DEEZNS_CONFIG = policyFile;
          # tracing-subscriber colours its output unless told not to, and
          # the escape codes would end up in the journal.
          NO_COLOR = "1";
        };

        serviceConfig = {
          ExecStart = lib.getExe cfg.package;
          Restart = "on-failure";

          User = "deezns";
          Group = "deezns";
          # The daemon creates its sockets itself, so it needs writable
          # directories under /run; 0755 lets clients reach the sockets,
          # whose own modes do the access control.
          RuntimeDirectory = [(runtimeDirectoryOf cfg.socketPath)];
          RuntimeDirectoryMode = "0755";
          UMask = "0077";

          # Hardening.  Everything the daemon does is: read the policy and
          # blocklists, listen on Unix sockets, read SO_PEERCRED, and talk
          # to nsncd over another Unix socket.
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          DevicePolicy = "closed";
          ProtectHostname = true;
          ProtectClock = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          # /proc/<pid> is not read today; drop ProcSubset (and loosen
          # ProtectProc) if the daemon starts consulting /proc/<pid>/status
          # for supplementary groups, as the README's future directions
          # suggest.
          ProtectProc = "invisible";
          ProcSubset = "pid";
          # No PrivateUsers: inside a user namespace, SO_PEERCRED would
          # report unmapped callers as the overflow UID (65534) and
          # per-user policy would stop working.
          # AF_UNIX only: upstream resolution is currently a stub.  Add
          # AF_INET and AF_INET6 once the daemon queries real DNS servers.
          RestrictAddressFamilies = ["AF_UNIX"];
          RestrictNamespaces = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          RemoveIPC = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = ["@system-service" "~@privileged" "~@resources"];
        };
      };
    }

    # ── nscd front-end ────────────────────────────────────────────────
    (lib.mkIf nscdFrontend {
      assertions = [
        {
          assertion = config.services.nscd.enableNsncd;
          message = ''
            services.deezns.frontend = "nscd" needs nsncd
            (services.nscd.enableNsncd): glibc's own nscd has its socket
            path compiled in and cannot be moved behind deezns.
          '';
        }
        {
          assertion = lib.hasPrefix "/run/" cfg.nscd.socketPath && lib.hasPrefix "/run/" cfg.nscd.nsncdSocketPath;
          message = ''
            services.deezns.nscd.socketPath and nsncdSocketPath must be
            under /run, where the services' RuntimeDirectories are created.
          '';
        }
        {
          assertion = lib.length (lib.unique [cfg.socketPath cfg.nscd.socketPath cfg.nscd.nsncdSocketPath]) == 3;
          message = ''
            services.deezns: the daemon's policy socket (${cfg.socketPath}),
            its nscd socket (${cfg.nscd.socketPath}) and nsncd's socket
            (${cfg.nscd.nsncdSocketPath}) must be three different paths.
          '';
        }
        {
          assertion = effectiveNsncdSocket != cfg.nscd.socketPath && effectiveNsncdSocket != cfg.socketPath;
          message = ''
            services.deezns: nscd.service's NSNCD_SOCKET_PATH
            (${toString effectiveNsncdSocket}) is one of the daemon's own
            socket paths; nsncd and deezns would fight over it.
          '';
        }
        {
          assertion = effectiveNsncdSocket == cfg.nscd.nsncdSocketPath;
          message = ''
            services.deezns: nscd.service's NSNCD_SOCKET_PATH
            (${toString effectiveNsncdSocket}) differs from
            services.deezns.nscd.nsncdSocketPath (${cfg.nscd.nsncdSocketPath}),
            where the daemon forwards requests.  Set the deezns option
            rather than the environment variable.
          '';
        }
      ];

      services.deezns.settings.nscd_frontend = {
        listen = cfg.nscd.socketPath;
        upstream = cfg.nscd.nsncdSocketPath;
      };

      # nsncd moves out of the way; its runtime directory follows its
      # socket so the two services never share one.
      systemd.services.nscd = {
        environment.NSNCD_SOCKET_PATH = cfg.nscd.nsncdSocketPath;
        serviceConfig.RuntimeDirectory = lib.mkForce (runtimeDirectoryOf cfg.nscd.nsncdSocketPath);
      };

      systemd.services.deezns.serviceConfig.RuntimeDirectory = [(runtimeDirectoryOf cfg.nscd.socketPath)];
    })

    # ── NSS module ────────────────────────────────────────────────────
    (lib.mkIf nssFrontend {
      # nscd performs every host lookup on the system's behalf (see the top
      # of this file), so it is the one client that must reach the socket.
      users.users.${config.services.nscd.user}.extraGroups = ["deezns"];

      system.nssModules = [cfg.package];
      # `[!UNAVAIL=return]`: glibc's default actions are SUCCESS=return and
      # continue for everything else, so this makes every status except
      # UNAVAIL final.  A denial (NOTFOUND) then stops the lookup instead
      # of falling through to `dns`, while a pass-through verdict, or a
      # daemon that is not running, returns UNAVAIL and the next source is
      # tried.
      # https://www.gnu.org/software/libc/manual/html_node/Actions-in-the-NSS-configuration.html
      system.nssDatabases.hosts = lib.mkOrder cfg.nssOrder ["deezns [!UNAVAIL=return]"];
    })
  ]);
}
