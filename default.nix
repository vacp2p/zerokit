{ pkgs }:

pkgs.rustPlatform.buildRustPackage {
  pname = "zerokit";
  version = "nightly";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  CARGO_HOME = "/tmp";

  meta = with pkgs.lib; {
    description = "Zerokit";
    license = licenses.mit;
  };
}