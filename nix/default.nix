{
  pkgs,
  rust-overlay,
  src,
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

  tools = pkgs.callPackage ./tools.nix {};
  version = tools.findKeyValue "^version = \"([a-f0-9.-]+)\"$" ../rln/Cargo.toml;

in targetPlatformPkgs.rustPlatform.buildRustPackage {
  cargo = rustToolchain;
  rustc = rustToolchain;

  pname = "zerokit";
  version = "${version}";

  inherit src;

  cargoHash = "sha256-WXxQ8mAPD/mPBSnLrunhbDyCAQ0D82t1MILbo+Vfcqk=";

  nativeBuildInputs = [ pkgs.rust-cbindgen pkgs.xz ];

  doCheck = false;

  buildPhase = ''
    export CARGO_HOME=$TMPDIR/cargo
    cargo build --lib \
      ${if release             then "--release" else ""} \
      ${if rust-target != null then "--target=${rust-target}" else ""} \
      ${if features != null    then "--features=${features}" else ""} \
      --manifest-path rln/Cargo.toml
  '';

  installPhase = ''
    set -eu
    mkdir -p $out/lib
    find target -type f -name 'librln.*' -not -path '*/deps/*' -exec cp -v '{}' "$out/lib/" \;

    mkdir -p $out/include
    cbindgen ./rln -l c > "$out/include/rln.h"
  '';

  meta = with pkgs.lib; {
    description = "Zerokit";
    license = licenses.mit;
  };
}
