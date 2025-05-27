{
  pkgs,
  rust-overlay,
  project,
  src ? ../.,
  release ? true,
  features ? "arkzkey",
  target-platform ? null,
  rust-target ? null,
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
  version = if src ? rev then src.rev else "nightly";

  # Improve caching of sources
  src = builtins.path { path = src; name = "zerokit"; };

  cargoLock = {
    lockFile = ../Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  doCheck = false;

  CARGO_HOME = "/tmp";

  buildPhase = ''
    cargo build --lib \
      ${if release             then "--release" else ""} \
      ${if rust-target != null then "--target=${rust-target}" else ""} \
      ${if features != null    then "--features=${features}" else ""} \
      --manifest-path ${project}/Cargo.toml
  '';

  installPhase = ''
    mkdir -p $out/
    for file in $(find target -name 'librln.*' | grep -v deps/); do
      mkdir -p $out/$(dirname $file)
      cp -r $file $out/$file
    done
  '';


  meta = with pkgs.lib; {
    description = "Zerokit";
    license = licenses.mit;
  };
}
