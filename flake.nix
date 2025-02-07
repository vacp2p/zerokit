{
  description = "A flake for building zerokit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
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
      pkgsFor = forAllSystems (
        system: import nixpkgs {
          inherit system;
          config = {
            android_sdk.accept_license = true;
            allowUnfree = true;
          };
          overlays =  [
            (final: prev: {
              androidEnvCustom = prev.callPackage ./nix/pkgs/android-sdk { };
              androidPkgs = final.androidEnvCustom.pkgs;
              androidShell = final.androidEnvCustom.shell;
            })
          ];
        }
      );
    in
    {
      packages = forAllSystems (system: let
        pkgs = pkgsFor.${system};
      in rec {
        zerokit-android-arm64 = pkgs.callPackage ./nix/default.nix { target-platform="aarch64-android-prebuilt"; rust-target= "aarch64-linux-android"; };
        #zerokit-android-arm   = pkgs.callPackage ./nix/default.nix { target-platform="armv7a-android-prebuilt"; rust-target= "armv7-linux-androideabi"; };
        default = zerokit-android-arm64;
      });
    };
}