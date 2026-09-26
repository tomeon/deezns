{nsncd, ...}:
# nixpkgs' nsncd with a prototype patch that lets NSS modules loaded
# into it learn the credentials of the process whose lookup they
# are serving (see the patch header).  Not used by the NixOS module
# yet.
nsncd.overrideAttrs (previous: {
  patches = (previous.patches or []) ++ [./nsncd-peer-cred.patch];
})
