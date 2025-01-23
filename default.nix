{ 
  pkgs,
  target-platform ? "aarch64-android-prebuilt",
}:

pkgs.pkgsCross.${target-platform}.rustPlatform.buildRustPackage {
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