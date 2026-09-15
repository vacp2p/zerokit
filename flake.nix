{
  description = "A flake for building zerokit";

  nixConfig = {
    extra-substituters = [ "https://nix-cache.status.im/" ];
    extra-trusted-public-keys = [ "nix-cache.status.im-1:x/93lOfLU+duPplwMSBR+OlY4+mo+dCN7n0mr4oPwgY=" ];
  };

  inputs = {
    # A commit from nixpkgs 25.11 release : https://github.com/NixOS/nixpkgs/tree/release-25.11
    nixpkgs.url = "github:NixOS/nixpkgs?rev=cd648d6ea62bc0ffba91e61fcfe5e33c1e2004b1";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      nativeSystems = [
        "x86_64-linux" "aarch64-linux"
        "x86_64-darwin" "aarch64-darwin"
        "i686-linux"
      ];
      forAllNativeSystems = nixpkgs.lib.genAttrs nativeSystems;

      pkgsFor = forAllNativeSystems (
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
      packages = forAllNativeSystems (system: let
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
      } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
        rln-windows-x86_64 = buildRln.override {
          target-platform = "mingwW64";
          rust-target = "x86_64-pc-windows-gnu";
          windows-gnu = true;
        };
      });

      devShells = forAllNativeSystems (system: let
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
