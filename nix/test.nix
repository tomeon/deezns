# NixOS VM test for the deezns module.
#
# Two machines: `resolver` runs dnsmasq as the upstream DNS server for the
# test names, and `client` runs deezns with a policy that exercises every
# feature of the daemon: the three blocklist formats, CEL string methods
# and regexes, the uid/gid/pid variables, all three rule verdicts, both
# default verdicts and the daemon's own address records.  Every name is
# looked up twice: directly against the resolver (which must always answer)
# and through the client's glibc (which must answer or refuse exactly as
# the policy says).
#
# The client runs the default nscd front-end; specialisations switch it to
# the NSS-module front-end and to a default-deny policy mid-test.
{lib, ...}: let
  # Every name the resolver serves, with its address.  Only these names
  # exist upstream; the expected NSS outcome is in the test script.
  records = {
    "allowed.test" = "192.0.2.1";
    "sub.allowed.test" = "192.0.2.2";
    "unlisted.test" = "192.0.2.3";
    "first.test" = "192.0.2.4";
    "first-other.test" = "192.0.2.5";

    "ads.hosts-format.test" = "192.0.2.10";
    "ok.hosts-format.test" = "192.0.2.11";
    "tracker.domains-format.test" = "192.0.2.20";
    "ok.domains-format.test" = "192.0.2.21";
    "adblock-format.test" = "192.0.2.30";
    "deep.sub.adblock-format.test" = "192.0.2.31";
    "exception.adblock-format.test" = "192.0.2.32";
    "notadblock-format.test" = "192.0.2.33";

    "evil.suffix.test" = "192.0.2.40";
    "tracking-pixel.test" = "192.0.2.41";
    "my-telemetry-host.test" = "192.0.2.42";
    "42.metrics.test" = "192.0.2.43";
    "abc.metrics.test" = "192.0.2.44";

    "skip.passthrough.test" = "192.0.2.50";
    "alice-only.test" = "192.0.2.60";
    "staff-only.test" = "192.0.2.61";
  };

  aliceUid = 1000;
  staffGid = 2000;
in {
  name = "deezns";

  nodes = {
    resolver = {
      services.dnsmasq = {
        enable = true;
        resolveLocalQueries = false;
        settings = {
          # Authoritative for the test names only: no upstream servers, no
          # /etc/hosts.
          no-resolv = true;
          no-hosts = true;
          host-record = lib.mapAttrsToList (name: address: "${name},${address}") records;
        };
      };
      networking.firewall = {
        allowedTCPPorts = [53];
        allowedUDPPorts = [53];
      };
    };

    client = {
      config,
      nodes,
      pkgs,
      ...
    }: {
      imports = [./module.nix];

      networking.nameservers = [nodes.resolver.networking.primaryIPAddress];

      services.deezns = {
        enable = true;
        settings = {
          default_verdict = "passthrough";

          blocklists = [
            {
              name = "hosts";
              path = pkgs.writeText "hosts-format.txt" ''
                # hosts-file format: exact names, one per address line.
                0.0.0.0 ads.hosts-format.test
                127.0.0.1 localhost
              '';
            }
            {
              name = "domains";
              path = pkgs.writeText "domains-format.txt" ''
                # domains-only format: exact names.
                tracker.domains-format.test
              '';
            }
            {
              name = "adblock";
              path = pkgs.writeText "adblock-format.txt" ''
                ! AdBlock format: the domain and every subdomain.
                ||adblock-format.test^
                ! Exceptions are ignored at this layer.
                @@||exception.adblock-format.test^
              '';
            }
          ];

          rules = [
            {
              note = "blocklists";
              expr = ''blocked_by("hosts") || blocked_by("domains") || blocked_by("adblock")'';
              verdict = "deny";
            }
            {
              note = "endsWith";
              expr = ''hostname.endsWith(".suffix.test")'';
              verdict = "deny";
            }
            {
              note = "startsWith";
              expr = ''hostname.startsWith("tracking-")'';
              verdict = "deny";
            }
            {
              note = "contains";
              expr = ''hostname.contains("telemetry")'';
              verdict = "deny";
            }
            {
              note = "matches";
              expr = ''hostname.matches("^[0-9]+\\.metrics\\.test$")'';
              verdict = "deny";
            }
            {
              note = "allow exact and suffix";
              expr = ''hostname == "allowed.test" || hostname.endsWith(".allowed.test")'';
              verdict = "allow";
            }
            {
              note = "first match wins (allow)";
              expr = ''hostname == "first.test"'';
              verdict = "allow";
            }
            {
              note = "first match wins (deny)";
              expr = ''hostname.startsWith("first")'';
              verdict = "deny";
            }
            {
              note = "explicit passthrough";
              expr = ''hostname.endsWith(".passthrough.test")'';
              verdict = "passthrough";
            }
            {
              note = "alice only";
              expr = ''uid == ${toString aliceUid} && pid > 0 && hostname == "alice-only.test"'';
              verdict = "allow";
            }
            {
              note = "everyone else: alice-only.test";
              expr = ''hostname == "alice-only.test"'';
              verdict = "deny";
            }
            {
              note = "staff only";
              expr = ''gid == ${toString staffGid} && hostname == "staff-only.test"'';
              verdict = "allow";
            }
            {
              note = "everyone else: staff-only.test";
              expr = ''hostname == "staff-only.test"'';
              verdict = "deny";
            }
            {
              # The daemon has a built-in record for this name, so an
              # allow verdict resolves it without asking upstream.
              note = "daemon-resolved";
              expr = ''hostname == "example.local"'';
              verdict = "allow";
            }
          ];
        };
      };

      # Switched to mid-test: the same policy with the other default
      # verdict, and the NSS-module front-end.
      specialisation = {
        default-deny.configuration.services.deezns.settings.default_verdict = lib.mkForce "deny";
        nss-module.configuration.services.deezns.frontend = "nss";
      };

      # A user that only nss-systemd knows, so `getent passwd dynuser`
      # proves that passwd lookups still reach nsncd through deezns.
      systemd.services.dynuser = {
        wantedBy = ["multi-user.target"];
        serviceConfig = {
          DynamicUser = true;
          ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
        };
      };

      # alice and carol may query the daemon directly; bob may not.
      users.users = {
        alice = {
          isNormalUser = true;
          uid = aliceUid;
          extraGroups = ["deezns"];
        };
        carol = {
          isNormalUser = true;
          uid = 1001;
          group = "staff";
          extraGroups = ["deezns"];
        };
        bob = {
          isNormalUser = true;
          uid = 1002;
        };
      };
      users.groups.staff.gid = staffGid;

      environment.systemPackages = [
        pkgs.dig
        # Talks to the daemon over its socket, bypassing glibc, so the
        # daemon sees the caller's own credentials.
        (pkgs.writers.writePython3Bin "deezns-query" {} ''
          import json
          import socket
          import sys

          sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
          sock.connect("${config.services.deezns.socketPath}")
          sock.sendall((json.dumps({"hostname": sys.argv[1]}) + "\n").encode())
          print(sock.makefile().readline().strip())
        '')
      ];
    };
  };

  testScript = {nodes, ...}: ''
    import json

    records = json.loads('${builtins.toJSON records}')
    resolver_ip = "${nodes.resolver.networking.primaryIPAddress}"
    socket_path = "${nodes.client.services.deezns.socketPath}"
    # Specialisations are reached through the base system, since
    # /run/current-system points at whichever one was switched to last.
    base_system = "${nodes.client.system.build.toplevel}"


    def upstream(name):
        """Addresses the resolver returns, bypassing NSS entirely."""
        out = client.succeed(f"dig +short +time=2 +tries=1 @{resolver_ip} {name} A")
        return sorted(out.split())


    def nss(name):
        """Addresses glibc returns for the name, or None if it has none."""
        status, out = client.execute(f"getent ahosts {name}")
        if status != 0:
            return None
        return sorted({line.split()[0] for line in out.splitlines()})


    def expect_resolved(name):
        addresses = upstream(name)
        assert addresses, f"{name} should be served upstream"
        assert nss(name) == addresses, f"{name} should resolve to {addresses} through NSS"


    def expect_blocked(name):
        assert upstream(name), f"{name} should be served upstream"
        assert nss(name) is None, f"{name} should be blocked by deezns"


    def query(user, name):
        """The daemon's verdict for `name` when `user` connects directly."""
        return json.loads(client.succeed(f"runuser -u {user} -- deezns-query {name}"))


    def nss_as(user, name):
        """Like nss(), for a lookup made by `user`."""
        status, out = client.execute(f"runuser -u {user} -- getent ahosts {name}")
        if status != 0:
            return None
        return sorted({line.split()[0] for line in out.splitlines()})


    def owner(path):
        return client.succeed(f"stat -c %U {path}").strip()


    start_all()
    resolver.wait_for_unit("dnsmasq.service")
    client.wait_for_unit("multi-user.target")
    client.wait_for_unit("deezns.service")
    client.wait_for_file(socket_path)
    client.wait_for_file("/run/nscd/socket")

    with subtest("The resolver serves every test name"):
        for name, address in records.items():
            assert upstream(name) == [address], f"{name} should resolve upstream to {address}"

    with subtest("deezns answers on nscd's socket, with nsncd behind it"):
        assert owner("/run/nscd/socket") == "deezns"
        assert owner("/run/nsncd/socket") == "nscd"
        client.succeed("systemctl show nscd -p Environment | grep NSNCD_SOCKET_PATH=/run/nsncd/socket")
        client.fail("grep -E '^hosts:.*deezns' /etc/nsswitch.conf")
        client.succeed("journalctl -u deezns | grep 'listening (nscd front-end)'")
        client.succeed("journalctl -u deezns | grep 'policy engine ready'")
        assert client.succeed("journalctl -u deezns | grep -c 'loaded blocklist'").strip() == "3"

    with subtest("Requests deezns does not judge reach nsncd unchanged"):
        # alice is in /etc/passwd; dynuser exists only through nss-systemd,
        # which NixOS loads into nsncd alone.
        client.succeed("getent passwd alice")
        client.succeed("getent passwd dynuser")
        client.succeed("getent group staff")

    with subtest("Names no rule matches pass through to dns"):
        expect_resolved("unlisted.test")

    with subtest("Allow rules resolve upstream, with exact and suffix matching"):
        expect_resolved("allowed.test")
        expect_resolved("sub.allowed.test")

    with subtest("Blocklists in hosts-file, domains-only and AdBlock formats"):
        expect_blocked("ads.hosts-format.test")
        expect_resolved("ok.hosts-format.test")
        expect_blocked("tracker.domains-format.test")
        expect_resolved("ok.domains-format.test")
        expect_blocked("adblock-format.test")
        expect_blocked("deep.sub.adblock-format.test")
        # `@@` exceptions are ignored by the blocklist loader.
        expect_blocked("exception.adblock-format.test")
        # AdBlock entries match whole labels, not string suffixes.
        expect_resolved("notadblock-format.test")

    with subtest("Hostnames are matched case-insensitively"):
        assert nss("ADS.Hosts-Format.TEST") is None
        assert nss("Allowed.TEST") == [records["allowed.test"]]

    with subtest("CEL string methods and regexes"):
        expect_blocked("evil.suffix.test")
        expect_blocked("tracking-pixel.test")
        expect_blocked("my-telemetry-host.test")
        expect_blocked("42.metrics.test")
        expect_resolved("abc.metrics.test")

    with subtest("The first matching rule wins"):
        expect_resolved("first.test")
        expect_blocked("first-other.test")

    with subtest("Denials are logged with the rule that fired"):
        client.succeed("journalctl -u deezns | grep DENIED | grep 'hostname=\"evil.suffix.test\"' | grep 'matched rule: endsWith'")

    with subtest("The daemon can answer with its own records"):
        # Upstream has never heard of the name; the daemon resolves it.
        assert upstream("example.local") == []
        assert nss("example.local") == ["10.0.0.1"]
        client.succeed("journalctl -u deezns | grep RESOLVED | grep 'hostname=\"example.local\"'")

    with subtest("Per-user rules apply to lookups made through glibc"):
        # Through nscd's socket the daemon sees the caller itself.
        assert nss_as("alice", "alice-only.test") == [records["alice-only.test"]]
        assert nss_as("carol", "alice-only.test") is None
        assert nss_as("carol", "staff-only.test") == [records["staff-only.test"]]
        assert nss_as("alice", "staff-only.test") is None
        assert nss_as("bob", "allowed.test") == [records["allowed.test"]]
        client.succeed(
            "journalctl -u deezns | grep 'hostname=\"alice-only.test\"' | grep 'peer.uid=${toString aliceUid} '"
        )
        client.succeed(
            "journalctl -u deezns | grep 'hostname=\"staff-only.test\"' | grep 'peer.gid=${toString staffGid} '"
        )

    with subtest("Per-user rules see the credentials of direct clients"):
        assert query("alice", "alice-only.test") == {"verdict": "PassThrough"}
        assert query("carol", "alice-only.test")["verdict"] == "Denied"
        assert query("carol", "staff-only.test") == {"verdict": "PassThrough"}
        assert query("alice", "staff-only.test")["verdict"] == "Denied"
        assert query("alice", "example.local") == {
            "verdict": "Resolved",
            "addresses": ["10.0.0.1"],
        }
        assert query("alice", "ads.hosts-format.test")["verdict"] == "Denied"

    with subtest("Only group members can talk to the daemon directly"):
        client.fail("runuser -u bob -- deezns-query allowed.test")

    with subtest("With nsncd stopped, deezns degrades but never lets a denial through"):
        client.systemctl("stop nscd.service")
        # Allowed names cannot be resolved (TRY_AGAIN), denied ones stay denied.
        assert nss("allowed.test") is None
        assert nss("ads.hosts-format.test") is None
        client.succeed("journalctl -u deezns | grep 'answering TRY_AGAIN'")
        # glibc serves what it can itself: /etc/passwd, but not nss-systemd.
        client.succeed("getent passwd alice")
        client.fail("getent passwd dynuser")
        client.systemctl("start nscd.service")
        client.wait_for_file("/run/nsncd/socket")
        expect_resolved("allowed.test")
        client.succeed("getent passwd dynuser")

    with subtest("The daemon is hardened"):
        # --threshold is on a 0-100 scale; the printed exposure level is a
        # tenth of it, so this fails once the unit scores above 2.0.
        client.succeed("systemd-analyze security --no-pager --threshold=20 deezns.service")

    with subtest("Without the daemon, lookups fall through to dns"):
        # Stopping the daemon removes /run/nscd/socket; glibc then resolves
        # in-process, unfiltered.
        client.systemctl("stop deezns.service")
        client.fail("test -e /run/nscd/socket")
        expect_resolved("ads.hosts-format.test")
        client.systemctl("start deezns.service")
        client.wait_for_file("/run/nscd/socket")
        expect_blocked("ads.hosts-format.test")

    with subtest("With default_verdict = deny, unmatched names are refused"):
        client.succeed(f"{base_system}/specialisation/default-deny/bin/switch-to-configuration test")
        client.wait_for_unit("deezns.service")
        client.wait_until_succeeds("deezns-query unlisted.test | grep -q Denied")
        expect_blocked("unlisted.test")
        expect_resolved("allowed.test")
        # An explicit passthrough verdict still hands the name to dns.
        expect_resolved("skip.passthrough.test")
        assert nss("example.local") == ["10.0.0.1"]

    with subtest("The NSS-module front-end blocks the same names"):
        client.succeed(f"{base_system}/specialisation/nss-module/bin/switch-to-configuration test")
        client.wait_for_unit("deezns.service")
        client.wait_for_unit("nscd.service")
        client.wait_for_file(socket_path)
        client.succeed(
            r"grep -E '^hosts:.* files .*deezns \[!UNAVAIL=return\] .*dns' /etc/nsswitch.conf"
        )
        assert owner("/run/nscd/socket") == "nscd"
        client.fail("test -e /run/nsncd/socket")
        expect_blocked("ads.hosts-format.test")
        expect_blocked("evil.suffix.test")
        expect_resolved("allowed.test")
        assert nss("example.local") == ["10.0.0.1"]

    with subtest("... but lookups through glibc carry nsncd's credentials"):
        # NixOS runs the NSS module inside nsncd, which is what connects to
        # the daemon, so the daemon sees nsncd's uid rather than alice's.
        nscd_uid = client.succeed("id -u nscd").strip()
        assert nss_as("alice", "alice-only.test") is None
        client.succeed(
            f"journalctl -u deezns | grep 'hostname=\"alice-only.test\"' | grep 'peer.uid={nscd_uid} '"
        )
  '';
}
