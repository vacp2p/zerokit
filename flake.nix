{
  description = "A flake for building zerokit";

  inputs = {
    # Version 24.11
    nixpkgs.url = "github:NixOS/nixpkgs?rev=f44bd8ca21e026135061a0a57dcf3d0775b67a49";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      stableSystems = [
        "x86_64-linux" "aarch64-linux"
        "x86_64-darwin" "aarch64-darwin"
        "x86_64-windows" "i686-linux"
        "i686-windows"
      ];
      forAllSystems = nixpkgs.lib.genAttrs stableSystems;
      overlays = [
        (import rust-overlay)
        (f: p: { inherit rust-overlay; })
      ];
      pkgsFor = forAllSystems (system: import nixpkgs { inherit system overlays; });
    in rec
    {
      packages = forAllSystems (system: let
        pkgs = pkgsFor.${system};
        buildPackage = pkgs.callPackage ./nix/default.nix;
        buildRln = (buildPackage { src = self; project = "rln"; }).override;
      in rec {
        rln = buildRln

        rln-linux-arm64 = buildRln {
          target-platform = "aarch64-multiplatform";
          rust-target = "aarch64-unknown-linux-gnu";
        };

        rln-android-arm64 = buildRln {
          target-platform = "aarch64-android-prebuilt";
          rust-target = "aarch64-linux-android";
        };

        rln-ios-arm64 = buildRln {
          target-platform = "aarch64-darwin";
          rust-target = "aarch64-apple-ios";
        };

        # TODO: Remove legacy name for RLN android library
        zerokit-android-arm64 = rln-android-arm64;

        default = rln;
      });

      devShells = forAllSystems (system: let
        pkgs = pkgsFor.${system};
      in {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            git cmake cargo-make rustup
            binaryen ninja gnuplot
            rust-bin.stable.latest.default
          ];
        };
      });
    };
}
