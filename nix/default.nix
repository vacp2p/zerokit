{
  pkgs,
  rust-overlay,
  target-platform ? "aarch64-android-prebuilt",
  rust-target ? "aarch64-linux-android",
}:

let
  # Use cross-compilation if target-platform is specified.
  targetPlatformPkgs = if target-platform != null
    then pkgs.pkgsCross.${target-platform}
    else pkgs;

  rust-bin = rust-overlay.lib.mkRustBin { } targetPlatformPkgs.buildPackages;

  # Use Rust and Cargo versions from rust-overlay.
  rustPlatform = targetPlatformPkgs.makeRustPlatform {
    cargo = rust-bin.stable.latest.minimal;
    rustc = rust-bin.stable.latest.minimal;
  };
in rustPlatform.buildRustPackage {
  pname = "zerokit";
  version = "nightly";

  src = ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  CARGO_HOME = "/tmp";

  buildPhase = ''
    pushd rln
    cargo rustc --crate-type=cdylib --release --lib --target=${rust-target}
    popd
  '';

  installPhase = ''
    mkdir -p $out/
    cp ./target/${rust-target}/release/librln.so $out/
  '';

  meta = with pkgs.lib; {
    description = "Zerokit";
    license = licenses.mit;
  };
}
