{
  pkgs,
  rust-overlay,
  src,
  release ? true,
  target-platform ? null,
  rust-target ? null,
  features ? null,
  windows-gnu ? false,
}:

let
  # Use cross-compilation if target-platform is specified.
  targetPlatformPkgs = if target-platform != null
    then pkgs.pkgsCross.${target-platform}
    else pkgs;

  crossCC = targetPlatformPkgs.stdenv.cc;
  rustToolchain =
    if windows-gnu then
      pkgs.buildPackages.rust-bin.stable.latest.default.override {
        targets = [ rust-target ];
      }
    else
      targetPlatformPkgs.rust-bin.stable.latest.default;
  rustPlatform =
    if windows-gnu then
      pkgs.buildPackages.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      }
    else
      targetPlatformPkgs.rustPlatform;

  rustTargetUnderscored = builtins.replaceStrings [ "-" ] [ "_" ] rust-target;
  targetEnvPrefix =
    "CARGO_TARGET_" + (pkgs.lib.toUpper rustTargetUnderscored);

  tools = pkgs.callPackage ./tools.nix {};
  version = tools.findKeyValue "^version = \"([a-f0-9.-]+)\"$" ../rln/Cargo.toml;

in rustPlatform.buildRustPackage {
  cargo = rustToolchain;
  rustc = rustToolchain;

  pname = "zerokit";
  version = "${version}";

  inherit src;

  cargoHash = "sha256-3wFnSJYUSQ01tQLe4nZGUZdoU1A9vsl9dpJU3vPeiHo=";

  nativeBuildInputs = [ ]
    ++ pkgs.lib.optional windows-gnu crossCC;

  env = pkgs.lib.optionalAttrs windows-gnu {
    "${targetEnvPrefix}_LINKER" =
      "${crossCC}/bin/${crossCC.targetPrefix}cc";
    "CC_${rustTargetUnderscored}" =
      "${crossCC}/bin/${crossCC.targetPrefix}cc";
    "CXX_${rustTargetUnderscored}" =
      "${crossCC}/bin/${crossCC.targetPrefix}c++";
    "AR_${rustTargetUnderscored}" =
      "${crossCC.bintools}/bin/${crossCC.targetPrefix}ar";
    "${targetEnvPrefix}_RUSTFLAGS" =
      "-L native=${targetPlatformPkgs.windows.pthreads}/lib";
  };

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
    mkdir -p $out/lib ${if windows-gnu then "$out/bin" else ""}
    ${if windows-gnu then ''
    find target -type f -name 'rln.dll' -not -path '*/deps/*' -exec cp -v '{}' "$out/bin/" \;
    find target -type f \( -name 'librln.a' -o -name 'librln.dll.a' \) -not -path '*/deps/*' -exec cp -v '{}' "$out/lib/" \;
    '' else ''
    find target -type f -name 'librln.*' -not -path '*/deps/*' -exec cp -v '{}' "$out/lib/" \;
    ''}

    mkdir -p $out/include
    cargo run --manifest-path rln/Cargo.toml --features headers --bin generate_headers
    cp -v rln.h "$out/include/rln.h"

    ${if windows-gnu then ''
    if [ ! -f "$out/bin/rln.dll" ] \
      || [ ! -f "$out/lib/librln.a" ] \
      || [ ! -f "$out/lib/librln.dll.a" ]; then
      echo "error: expected Windows RLN libraries and rln.dll under target/" >&2
      exit 1
    fi
    '' else ""}
  '';

  doCheck = !windows-gnu;
  dontStrip = windows-gnu;

  meta = with pkgs.lib; {
    description = "Zerokit";
    license = licenses.mit;
  };
}
