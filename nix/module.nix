# NixOS module for deezns: runs the daemon as a hardened systemd service and
# plugs libnss_deezns.so.2 into the system's NSS configuration.
#
# How NSS works on NixOS matters here.  Third-party NSS modules are not
# loadable by arbitrary processes (glibc searches only its own lib directory
# and LD_LIBRARY_PATH); NixOS instead lists them in `system.nssModules` and
# points nscd (nsncd by default) at them, and every process' host lookups go
# through nscd's socket.  Two consequences for deezns:
#
#   * Only nscd talks to the daemon, so nscd's user needs access to the
#     daemon's socket (the daemon creates it with mode 0660).
#   * SO_PEERCRED identifies nscd, not the process that called
#     getaddrinfo(), so the `uid`, `gid` and `pid` CEL variables carry
#     nscd's credentials for every lookup made through glibc.  Hostname and
#     blocklist rules work as documented; per-user rules only apply to
#     clients that connect to the socket directly.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.deezns;

  settingsFormat = pkgs.formats.toml {};
  policyFile = settingsFormat.generate "deezns-policy.toml" cfg.settings;

  socketDir = dirOf cfg.socketPath;
in {
  options.services.deezns = {
    enable = lib.mkEnableOption "deezns, a DNS policy daemon consulted by glibc through an NSS module";

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
        The Unix socket the daemon listens on, as compiled into
        {option}`services.deezns.package`.  Read-only: to change it, rebuild
        the package (see the description of that option).
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
        Position of `deezns` in the `hosts` line of `/etc/nsswitch.conf`,
        as a `lib.mkOrder` priority.  NixOS places `mymachines` at 400,
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
              name to the next NSS source (normally `dns`); `deny` answers
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
                  description = "CEL expression over `hostname`, `uid`, `gid`, `pid` and `blocked_by(name)`.";
                };
                verdict = lib.mkOption {
                  type = lib.types.enum ["allow" "deny" "passthrough"];
                  description = "What to do when the expression is true.";
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

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.services.nscd.enable;
        message = ''
          services.deezns needs services.nscd.enable: NixOS only loads NSS
          modules such as libnss_deezns.so.2 through nscd.
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
    # anything that should be able to query it directly needs group `deezns`.
    users.users.deezns = {
      isSystemUser = true;
      group = "deezns";
      description = "deezns DNS policy daemon";
    };
    users.groups.deezns = {};

    # nscd performs every host lookup on the system's behalf (see the top of
    # this file), so it is the one client that must reach the socket.
    users.users.${config.services.nscd.user}.extraGroups = ["deezns"];

    system.nssModules = [cfg.package];
    # `[!UNAVAIL=return]`: glibc's default actions are SUCCESS=return and
    # continue for everything else, so this makes every status except
    # UNAVAIL final.  A denial (NOTFOUND) then stops the lookup instead of
    # falling through to `dns`, while a pass-through verdict, or a daemon
    # that is not running, returns UNAVAIL and the next source is tried.
    # https://www.gnu.org/software/libc/manual/html_node/Actions-in-the-NSS-configuration.html
    system.nssDatabases.hosts = lib.mkOrder cfg.nssOrder ["deezns [!UNAVAIL=return]"];

    systemd.services.deezns = {
      description = "deezns DNS policy daemon";
      documentation = ["https://github.com/tomeon/deezns"];
      wantedBy = ["multi-user.target"];
      # Be up before anything that needs name resolution, nscd included:
      # while the daemon is down the NSS module reports UNAVAIL and lookups
      # go straight to `dns`, unfiltered.
      before = ["nss-lookup.target" "nscd.service"];
      wants = ["nss-lookup.target"];

      environment = {
        DEEZNS_CONFIG = policyFile;
        # tracing-subscriber colours its output unless told not to, and the
        # escape codes would end up in the journal.
        NO_COLOR = "1";
      };

      serviceConfig = {
        ExecStart = lib.getExe cfg.package;
        Restart = "on-failure";

        User = "deezns";
        Group = "deezns";
        # The daemon creates the socket itself, so it needs a writable
        # directory under /run; 0755 lets clients reach the socket, whose
        # own mode (0660) does the access control.
        RuntimeDirectory = lib.removePrefix "/run/" socketDir;
        RuntimeDirectoryMode = "0755";
        UMask = "0077";

        # Hardening.  Everything the daemon does is: read the policy and
        # blocklists, listen on one Unix socket, read SO_PEERCRED.
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
        # No PrivateUsers: inside a user namespace, SO_PEERCRED would report
        # unmapped callers as the overflow UID (65534) and per-user policy
        # would stop working.
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
  };
}
