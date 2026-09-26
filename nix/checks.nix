{
  lib,
  self,
  ...
}: {
  perSystem = {pkgs, ...}: let
    importCheck = lib.flip lib.pipe [
      (lib.flip import {localFlake = self;})
      (lib.flip pkgs.callPackage {})
    ];
  in {
    checks = {
      # The VM test boots two machines (a resolver and a deezns client),
      # so it needs KVM, or a builder that declares the `kvm` feature and
      # lets QEMU fall back to emulation.  See "NixOS test" in AGENTS.md.
      nixos = importCheck ./checks/nixos.nix;

      # The module's assertions, evaluated against accepted and refused
      # configurations; nothing is built.
      module = importCheck ./checks/module.nix;
    };
  };
}
