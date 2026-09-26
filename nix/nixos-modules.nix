{
  config,
  flake-parts-lib,
  moduleWithSystem,
  ...
}: {
  flake = {
    nixosModules = {
      default = config.flake.nixosModules.deezns;
      deezns = flake-parts-lib.importApply ./modules/nixos/deezns.nix {
        inherit moduleWithSystem;
      };
    };
  };
}
