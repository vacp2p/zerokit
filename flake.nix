{
  description = "A flake for building zerokit";

  nixConfig = {
    extra-substituters = [ "https://nix-cache.status.im/" ];
    extra-trusted-public-keys = [ "nix-cache.status.im-1:x/93lOfLU+duPplwMSBR+OlY4+mo+dCN7n0mr4oPwgY=" ];
  };

  inputs = {
    # A commit from nixpkgs 25.11 release : https://github.com/NixOS/nixpkgs/tree/release-25.11
    # Bumped from rev 23d72dab… (2026-02-07) to a post-2026-04-24 rev so that
    # rustPlatform.fetchCargoVendor uses `fetch-cargo-vendor-util-v2.py`, which
    # sets a `nixpkgs-fetchCargoVendor/2` User-Agent. The previous script sent
    # no User-Agent and crates.io returns 403 for empty-UA requests, breaking
    # `nix build .#rln` for anyone without a warm vendor cache.
    nixpkgs.url = "github:NixOS/nixpkgs?rev=cd648d6ea62bc0ffba91e61fcfe5e33c1e2004b1";
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

      pkgsFor = forAllSystems (
        system: import nixpkgs {
          inherit system;
          config = {
            android_sdk.accept_license = true;
            allowUnfree = true;
          };
          overlays = [
            (import rust-overlay)
            (f: p: { inherit rust-overlay; })
          ];
        }
      );
    in rec
    {
      packages = forAllSystems (system: let
        pkgs = pkgsFor.${system};

        buildRln = pkgs.callPackage ./nix/default.nix {
          src = self;
        };

      in rec {
        rln = buildRln;

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

        # TODO(backlog): Remove legacy name for RLN android library
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
