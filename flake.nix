{
  description = "A flake for building zerokit";

  inputs = {
    # Version 24.11
    nixpkgs.url = "github:NixOS/nixpkgs?rev=f44bd8ca21e026135061a0a57dcf3d0775b67a49";
  };

  outputs = { self, nixpkgs }: 
    let
      stableSystems = [
        "x86_64-linux" "aarch64-linux"
        "x86_64-darwin" "aarch64-darwin"
        "x86_64-windows" "i686-linux"
        "i686-windows"
      ];
      forAllSystems = nixpkgs.lib.genAttrs stableSystems;
      pkgsFor = forAllSystems (system: import nixpkgs { inherit system; });
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
          inputsFrom = [
            packages.${system}.default
          ];
        };
      });
    };
}