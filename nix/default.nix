{ 
  pkgs,
  target-platform ? "aarch64-android",
  rust-target ? "aarch64-linux-android",
}:

pkgs.pkgsCross.${target-platform}.rustPlatform.buildRustPackage {
  pname = "zerokit";
  version = "nightly";

  src = ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  ANDROID_NDK_HOME="${pkgs.androidPkgs.ndk}";
  CARGO_HOME = "/tmp";

  buildPhase = ''
    pushd rln
    cargo rustc --crate-type=cdylib --release --lib --target=${rust-target}
    popd
  '';

  installPhase = ''
    mkdir -p $out/build/
    cp -r ./target/release/librln.so $out/build/
  '';

  meta = with pkgs.lib; {
    description = "Zerokit";
    license = licenses.mit;
  };
}