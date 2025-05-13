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
      overlays = [ (import rust-overlay) ];
      pkgsFor = forAllSystems (system: import nixpkgs { inherit system overlays; });
    in rec
    {
      packages = forAllSystems (system: let
        pkgs = pkgsFor.${system};
      in rec {
        zerokit-android-arm64 = pkgs.callPackage ./nix/default.nix { target-platform="aarch64-android-prebuilt"; rust-target= "aarch64-linux-android"; };
        default = zerokit-android-arm64;
      });

      devShells = forAllSystems (system: let
        pkgs = pkgsFor.${system};
      in {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            git
            cmake
            cargo-make
            binaryen
            ninja
            gnuplot
            rustup
            xz
            rust-bin.stable.latest.default
          ];
          # Shared library liblzma.so.5 used by wasm-pack
          shellHook = ''
            export LD_LIBRARY_PATH="${pkgs.xz.out}/lib:$LD_LIBRARY_PATH"
          '';
        };
      });
    };
}