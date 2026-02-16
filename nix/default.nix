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

  rustToolchain = targetPlatformPkgs.rust-bin.stable.latest.default;

in targetPlatformPkgs.rustPlatform.buildRustPackage {
  cargo = rustToolchain;
  rustc = rustToolchain;

  pname = "zerokit";
  version = if src ? rev then src.rev else "nightly";

  # Improve caching of sources
  src = pkgs.fetchFromGitHub {
    owner = "vacp2p";
    repo = "zerokit";
    rev  = "3160d9504d07791f2fc9b610948a6cf9a58ed488";
    sha256 = "sha256-SbDoBElFYJ4cYebltxlO2lYnz6qOaDAVY6aNJ5bqHDE=";
  };

  cargoHash = "sha256-Kik/vqiozy0W9z+KHu0DQ+g6veYAbXvBQ8XqvdkRHOE=";

  nativeBuildInputs = [ pkgs.rust-cbindgen pkgs.xz ];

  doCheck = false;

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
    export CARGO_HOME=$TMPDIR/cargo
    cbindgen ./rln -l c > "$out/include/rln.h"
  '';

  meta = with pkgs.lib; {
    description = "Zerokit";
    license = licenses.mit;
  };
}
