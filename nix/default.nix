{ 
  pkgs,
  target-platform ? "aarch64-android-prebuilt",
  rust-target ? "aarch64-linux-android",
  lib,
}:

let
  rustVersion = "1.84.1";

  # Define each Rust standard library archive separately
  rustStdX86_64LinuxAndroid = pkgs.fetchurl {
    url = "https://static.rust-lang.org/dist/2025-01-30/rust-std-1.84.1-x86_64-linux-android.tar.gz ";
    sha256 = "sha256-Iu9hg4w/4uMfJCwPWw9SCKvPGZoyOeP4uW+ixAf63Is=";  # Replace with actual SHA256 hash
  };

  rustStdAarch64LinuxAndroid = pkgs.fetchurl {
    url = "https://static.rust-lang.org/dist/2025-01-30/rust-std-1.84.1-aarch64-linux-android.tar.gz";
    sha256 = "sha256-NMmJW3A7JJeu+epf9R3pWKKr/dUQnDCo3QmFhkVll2o=";  # Replace with actual SHA256 hash
  };

  rustStdX86_64UnknownLinuxGnu = pkgs.fetchurl {
    url = "https://static.rust-lang.org/dist/rust-1.84.1-x86_64-unknown-linux-gnu.tar.xz";
    sha256 = "sha256-5PMzF5TxoyxW+DcDCRLYC1o9lmn0tJfJFhHWW9atqXs=";  # Replace with actual SHA256 hash
  };

  rustupInit = pkgs.fetchurl {
    url = "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init";
    sha256 = "sha256-au7OaZPpAnCJg7IJ0EwNHbsU67QF3bh971eNQfkg9W0=";  # Replace with actual SHA256 hash for rustup-init
  };
in


pkgs.rustPlatform.buildRustPackage {
  pname = "zerokit";
  version = "nightly";

  src = ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
    allowBuiltinFetchGit = true;
  };


  # Dependencies that should only exist in the build environment.
  nativeBuildInputs = with pkgs; [
    unzip
    xz
    clang
    cmake
    gcc
    which
  ];

  ANDROID_NDK_HOME="${pkgs.androidPkgs.ndk}";
  CARGO_HOME = "/tmp";

  configurePhase = ''
    echo $USER
    echo $UID
    # Create directories for Rust installation
    mkdir -p ./rust-install/rust-${rustVersion}-x86_64-unknown-linux-gnu

    # Extract Rust standard libraries
    tar -xvzf ${rustStdX86_64LinuxAndroid} 
    tar -xvzf ${rustStdAarch64LinuxAndroid}
    tar -xvf ${rustStdX86_64UnknownLinuxGnu} -C ./rust-install/rust-${rustVersion}-x86_64-unknown-linux-gnu

    patchShebangs .
    # Install STD's
    chmod +x ./rust-std-1.84.1-x86_64-linux-android/install.sh
    chmod +x ./rust-std-1.84.1-aarch64-linux-android/install.sh
    
    ./rust-std-1.84.1-x86_64-linux-android/install.sh --prefix=./rust-install/rust-${rustVersion}-x86_64-unknown-linux-gnu --verbose
    ./rust-std-1.84.1-aarch64-linux-android/install.sh --prefix=./rust-install/rust-${rustVersion}-x86_64-unknown-linux-gnu --verbose

    # Initialize rustup
    ${rustupInit} --default-toolchain none -y --verbose

    # Link custom toolchain
    . "./.cargo/env"
    cargo --version
    which cargo
    rustup
    rustup toolchain link rust-toolchain-${rustVersion} ./rust-install/rust-${rustVersion}-x86_64-unknown-linux-gnu
    rustup default rust-toolchain-${rustVersion}

    # Set environment variables for Android NDK
    export CC=/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android25-clang
    export CXX=/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android25-clang++
    export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android25-clang
  '';

  buildPhase = ''
    pushd rln
    cargo rustc --crate-type=cdylib --release --lib --target=x86_64-linux-android
    popd
  '';

  installPhase = ''
    mkdir -p $out/
    cp ./target/${rust-target}/release/librln.so $out/
  '';

  meta = with pkgs.lib; {
    description = "Zerokit";
    license = licenses.mit;
  };
}