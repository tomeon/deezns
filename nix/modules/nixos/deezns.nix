# NixOS module for deezns: runs the daemon as a hardened systemd service and
# plugs it into the system's name resolution.
#
# How NSS works on NixOS matters here.  Third-party NSS modules are not
# loadable by arbitrary processes (glibc searches only its own lib directory
# and LD_LIBRARY_PATH); NixOS instead lists them in `system.nssModules` and
# points nscd (nsncd by default) at them, and every process' lookups go
# through nscd's socket.  The daemon has three front-ends, each a section of
# its settings with its own `enable`, in any combination:
#
#   * `nscd_frontend` (enabled by default): the daemon itself answers on
#     nscd's socket, /run/nscd/socket, and nsncd is moved to another path
#     behind it.  Host lookups are judged with the credentials of the
#     process that asked; everything else is forwarded to nsncd unchanged.
#
#   * `dns_frontend`: the daemon is the machine's DNS server on loopback.
#     Callers are identified from their sockets: uid always, gid and pid
#     with `identify_processes`, for which the unit is granted
#     CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE.  Programs with their own DNS
#     client are covered too.  On its own, it also makes nsncd stop handling
#     host lookups (`NSNCD_IGNORE_HOSTS`), so glibc resolves in-process
#     through resolv.conf and each query comes from the caller's own socket.
#
#   * `nss_frontend`: the classic arrangement, libnss_deezns.so.2 in
#     nsswitch.conf.  On NixOS it runs inside nsncd, so `uid`, `gid` and
#     `pid` carry nsncd's credentials for every lookup made through glibc;
#     hostname and blocklist rules work as documented.
#
# Combined, a lookup is judged once, by the first front-end it reaches:
#
#   glibc -> [nscd front-end] -> nsncd -> [NSS module] -> dns -> [DNS front-end]
#
# The daemon treats `nscd_user` as a relay on the listeners behind an
# enabled front-end (see src/relay.rs); the module keeps nsncd resolving
# host lookups whenever the nscd front-end or the NSS module needs it to.
{moduleWithSystem}:
moduleWithSystem (
  {config, ...} @ perSystem: {
    config,
    lib,
    pkgs,
    ...
  }: let
    cfg = config.services.deezns;
    inherit (cfg.settings) nscd_frontend dns_frontend;

    settingsFormat = pkgs.formats.toml {};
    # TOML has no null; unset optional settings are simply left out.
    policyFile = settingsFormat.generate "deezns-policy.toml" (lib.filterAttrsRecursive (_: v: v != null) cfg.settings);

    # The name of a directory under /run, for RuntimeDirectory=.
    runtimeDirectoryOf = path: lib.removePrefix "/run/" (dirOf path);

    nscdFrontend = nscd_frontend.enable;
    dnsFrontend = dns_frontend.enable;
    nssFrontend = cfg.settings.nss_frontend.enable;

    # `dns` in the `hosts` line of nsswitch.conf, as NixOS orders it
    # (nixos/modules/config/nsswitch.nix).
    dnsNssOrder = 1499;

    # The address part of "host:port" or "[v6]:port": everything before the
    # last colon, minus IPv6 brackets.
    listenAddress = let
      parts = lib.splitString ":" dns_frontend.listen;
      address = lib.concatStringsSep ":" (lib.init parts);
    in
      if lib.length parts < 2 || address == ""
      then null
      else lib.removePrefix "[" (lib.removeSuffix "]" address);

    # Capabilities the daemon keeps: none, unless it serves DNS (port 53) and
    # is allowed to look up which process is behind a query (listing another
    # user's /proc/<pid>/fd needs CAP_DAC_READ_SEARCH, following the links
    # CAP_SYS_PTRACE).
    capabilities =
      lib.optional dnsFrontend "CAP_NET_BIND_SERVICE"
      ++ lib.optionals (dnsFrontend && dns_frontend.identify_processes) ["CAP_DAC_READ_SEARCH" "CAP_SYS_PTRACE"];

    capabilitySetting = lib.concatStringsSep " " capabilities;

    nscdEnvironment = config.systemd.services.nscd.environment;
    effectiveNsncdSocket = nscdEnvironment.NSNCD_SOCKET_PATH or null;
  in {
    options.services.deezns = {
      enable = lib.mkEnableOption "deezns, a DNS policy daemon consulted by glibc through nscd or an NSS module";

      package = lib.mkOption {
        type = lib.types.package;
        default = perSystem.config.packages.deezns;
        defaultText = "github:tomeon/deezns#deezns";
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

      nssOrder = lib.mkOption {
        type = lib.types.int;
        default =
          if config.services.resolved.enable
          then 500
          else 1000;
        defaultText = lib.literalExpression "if config.services.resolved.enable then 500 else 1000";
        description = ''
          With {option}`services.deezns.settings.nss_frontend.enable` set: the
          position of `deezns` in the `hosts` line of `/etc/nsswitch.conf`, as
          a `lib.mkOrder` priority.  NixOS places `mymachines` at 400,
          `resolve` at 501, `files` at 998, `myhostname` at 999 and `dns` at
          1499.

          The default puts deezns after `files` (so `/etc/hosts` entries are
          never subject to policy) and before `dns`.  With systemd-resolved
          enabled, `resolve` answers before `files` and stops the lookup, so
          deezns is moved ahead of it; names from `/etc/hosts` are then
          evaluated against the policy too.  With the DNS front-end but not
          the nscd front-end enabled, it must stay before `dns`.
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

            nscd_user = lib.mkOption {
              type = lib.types.str;
              default = config.services.nscd.user;
              defaultText = lib.literalExpression "config.services.nscd.user";
              description = ''
                The user nscd (nsncd) runs as.  The lookups it makes for a
                front-end in front of it have been judged already, so the
                daemon passes them through: on the policy socket when the nscd
                front-end is enabled, on the DNS front-end when the nscd
                front-end or the NSS module is.
              '';
            };

            nscd_frontend = lib.mkOption {
              default = {};
              description = ''
                The nscd front-end: the daemon listens on nscd's socket in
                place of nsncd, which is moved behind it.  Host lookups are
                judged with the credentials of the process that asked; all
                other requests are forwarded to nsncd unchanged.  Requires
                nsncd ({option}`services.nscd.enableNsncd`).
              '';
              type = lib.types.submodule {
                freeformType = settingsFormat.type;
                options = {
                  enable = lib.mkOption {
                    type = lib.types.bool;
                    default = true;
                    description = "Whether to enable the nscd front-end.";
                  };
                  listen = lib.mkOption {
                    type = lib.types.path;
                    default = "/run/nscd/socket";
                    description = ''
                      The socket glibc's nscd client connects to.  glibc has
                      this path compiled in (`/var/run/nscd/socket`, and
                      `/var/run` is `/run`), so there is normally no reason to
                      change it.
                    '';
                  };
                  upstream = lib.mkOption {
                    type = lib.types.path;
                    default = "/run/nsncd/socket";
                    description = ''
                      Where nsncd listens instead, and where the daemon
                      forwards the requests it does not answer itself.  Set on
                      `nscd.service` as `NSNCD_SOCKET_PATH`; must be under
                      `/run` and differ from both `listen` and
                      {option}`services.deezns.socketPath`.
                    '';
                  };
                };
              };
            };

            dns_frontend = lib.mkOption {
              default = {};
              description = ''
                The DNS front-end: the daemon serves DNS on `listen` and is
                made the first nameserver, so every resolver on the machine,
                glibc or not, goes through the policy.  Callers are
                identified from their sockets.

                Enabled on its own, nsncd stops handling host lookups so that
                glibc resolves in-process and its queries, too, come from the
                caller's own socket.  With the nscd front-end or the NSS
                module enabled as well, nsncd keeps handling them and
                glibc's lookups are judged there.
              '';
              type = lib.types.submodule {
                freeformType = settingsFormat.type;
                options = {
                  enable = lib.mkOption {
                    type = lib.types.bool;
                    default = false;
                    description = "Whether to enable the DNS front-end.";
                  };
                  listen = lib.mkOption {
                    type = lib.types.str;
                    default = "127.0.0.1:53";
                    description = ''
                      Address and port to serve DNS on, over UDP and TCP.
                      glibc only ever queries port 53; the daemon is granted
                      `CAP_NET_BIND_SERVICE` for it.  The address is put first
                      in `networking.nameservers`.
                    '';
                  };
                  upstream = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    example = "192.0.2.53:53";
                    description = ''
                      The real DNS server, as `address:port`, that answers the
                      queries the policy lets through.  Required when the
                      front-end is enabled.
                    '';
                  };
                  identify_processes = lib.mkOption {
                    type = lib.types.bool;
                    default = false;
                    description = ''
                      Find the process behind a query in `/proc/<pid>/fd`,
                      giving rules `gid` and `pid` as well as `uid`; the unit
                      is granted `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE`
                      for it.  Off by default because `CAP_DAC_READ_SEARCH`
                      lets the daemon read any file its sandbox exposes,
                      `/etc/shadow` included; the socket tables give the uid
                      regardless, and `gid` and `pid` are then `-1`.
                    '';
                  };
                };
              };
            };

            nss_frontend = lib.mkOption {
              default = {};
              description = ''
                The NSS module: `libnss_deezns.so.2` is added to the `hosts`
                line of `/etc/nsswitch.conf` at
                {option}`services.deezns.nssOrder`.  Because NixOS runs NSS
                modules inside nsncd, the daemon then sees nsncd's uid, gid
                and pid for every lookup made through glibc; only clients of
                the daemon's own socket are identified individually.
              '';
              type = lib.types.submodule {
                freeformType = settingsFormat.type;
                options.enable = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = "Whether to enable the NSS module.";
                };
              };
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
            assertion = (nscdFrontend || dnsFrontend || nssFrontend) -> config.services.nscd.enable;
            message = ''
              services.deezns needs services.nscd.enable: NixOS routes name
              lookups through nscd, and every deezns front-end builds on that.
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
            # to nsncd over another Unix socket; as the DNS server it also
            # binds port 53, talks to the upstream resolver and reads /proc.
            CapabilityBoundingSet = capabilitySetting;
            AmbientCapabilities = capabilitySetting;
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
            # Other users' processes stay hidden; with CAP_SYS_PTRACE (the
            # DNS front-end identifying processes) the kernel shows them
            # anyway, which is exactly what that mode needs.  The DNS
            # front-end also reads /proc/net, so it cannot live with
            # ProcSubset=pid.
            ProtectProc = "invisible";
            ProcSubset =
              if dnsFrontend
              then "all"
              else "pid";
            # No PrivateUsers: inside a user namespace, SO_PEERCRED would
            # report unmapped callers as the overflow UID (65534) and
            # per-user policy would stop working.
            # AF_UNIX only, unless the daemon serves and forwards DNS.
            RestrictAddressFamilies = ["AF_UNIX"] ++ lib.optionals dnsFrontend ["AF_INET" "AF_INET6"];
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
              services.deezns.settings.nscd_frontend needs nsncd
              (services.nscd.enableNsncd): glibc's own nscd has its socket
              path compiled in and cannot be moved behind deezns.
            '';
          }
          {
            assertion = lib.hasPrefix "/run/" nscd_frontend.listen && lib.hasPrefix "/run/" nscd_frontend.upstream;
            message = ''
              services.deezns.settings.nscd_frontend.listen and upstream must
              be under /run, where the services' RuntimeDirectories are created.
            '';
          }
          {
            assertion = lib.length (lib.unique [cfg.socketPath nscd_frontend.listen nscd_frontend.upstream]) == 3;
            message = ''
              services.deezns: the daemon's policy socket (${cfg.socketPath}),
              its nscd socket (${nscd_frontend.listen}) and nsncd's socket
              (${nscd_frontend.upstream}) must be three different paths.
            '';
          }
          {
            assertion = effectiveNsncdSocket != nscd_frontend.listen && effectiveNsncdSocket != cfg.socketPath;
            message = ''
              services.deezns: nscd.service's NSNCD_SOCKET_PATH
              (${toString effectiveNsncdSocket}) is one of the daemon's own
              socket paths; nsncd and deezns would fight over it.
            '';
          }
          {
            assertion = effectiveNsncdSocket == nscd_frontend.upstream;
            message = ''
              services.deezns: nscd.service's NSNCD_SOCKET_PATH
              (${toString effectiveNsncdSocket}) differs from
              services.deezns.settings.nscd_frontend.upstream
              (${nscd_frontend.upstream}), where the daemon forwards requests.
              Set the deezns setting rather than the environment variable.
            '';
          }
        ];

        # nsncd moves out of the way; its runtime directory follows its
        # socket so the two services never share one.
        systemd.services.nscd = {
          environment.NSNCD_SOCKET_PATH = nscd_frontend.upstream;
          serviceConfig.RuntimeDirectory = lib.mkForce (runtimeDirectoryOf nscd_frontend.upstream);
        };

        systemd.services.deezns.serviceConfig.RuntimeDirectory = [(runtimeDirectoryOf nscd_frontend.listen)];
      })

      # ── DNS front-end ─────────────────────────────────────────────────
      (lib.mkIf dnsFrontend {
        assertions = [
          {
            assertion = dns_frontend.upstream != null;
            message = ''
              services.deezns.settings.dns_frontend needs an upstream, the DNS
              server that answers the queries the policy lets through.
            '';
          }
          {
            assertion = listenAddress != null;
            message = ''
              services.deezns.settings.dns_frontend.listen (${dns_frontend.listen})
              must be "address:port".
            '';
          }
          {
            assertion = config.services.nscd.enableNsncd;
            message = ''
              services.deezns.settings.dns_frontend needs nsncd
              (services.nscd.enableNsncd), which can be told to leave host
              lookups to glibc with NSNCD_IGNORE_HOSTS.
            '';
          }
          {
            assertion = nssFrontend && !nscdFrontend -> cfg.nssOrder < dnsNssOrder;
            message = ''
              services.deezns.nssOrder (${toString cfg.nssOrder}) must be below
              ${toString dnsNssOrder}, before `dns` in nsswitch.conf, when the
              NSS module and the DNS front-end are enabled without the nscd
              front-end: the DNS front-end then passes nsncd's queries through,
              trusting the NSS module to have judged them.
            '';
          }
          {
            assertion = !config.services.resolved.enable;
            message = ''
              services.deezns.settings.dns_frontend does not work with
              systemd-resolved (services.resolved.enable): its stub resolver
              would sit between the applications and the daemon, so every
              query would identify systemd-resolved rather than the program
              that asked, and its cache would be shared across users.
            '';
          }
        ];

        # Alone, nsncd answers nothing for host lookups, so glibc performs
        # them in each process itself, through resolv.conf, and the DNS
        # query leaves the caller's own socket.  The other front-ends need
        # nsncd to keep handling them.
        systemd.services.nscd.environment = lib.mkIf (!nscdFrontend && !nssFrontend) {
          NSNCD_IGNORE_HOSTS = "true";
        };

        # First nameserver.  openresolv then writes the daemon alone into
        # resolv.conf (`resolv_conf_local_only` drops the other nameservers
        # once a local one is present), so with the daemon down lookups
        # fail rather than go around it.
        networking.nameservers = lib.mkBefore [listenAddress];
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
)
