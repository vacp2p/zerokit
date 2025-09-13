{
  pkgs,
  rust-overlay,
  project,
  src ? ../.,
  release ? true,
  target-platform ? null,
  rust-target ? null,
  features ? null,
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
    lockFile = src + "/Cargo.lock";
    allowBuiltinFetchGit = true;
  };

  nativeBuildInputs = [ pkgs.rust-cbindgen ];

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
    set -eu
    mkdir -p $out/lib
    find target -type f -name 'librln.*' -not -path '*/deps/*' -exec cp -v '{}' "$out/lib/" \;
    mkdir -p $out/include
    cbindgen ${src}/rln -l c > "$out/include/rln.h"
  '';


  meta = with pkgs.lib; {
    description = "Zerokit";
    license = licenses.mit;
  };
}
