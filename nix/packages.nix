_: {
  perSystem = {
    config,
    pkgs,
    ...
  }: {
    packages = {
      default = config.packages.deezns;
      deezns = pkgs.callPackage ./pkgs/deezns {};
      nsncd = pkgs.callPackage ./pkgs/nsncd {};
    };
  };
}
