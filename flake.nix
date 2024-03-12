{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      # TODO(XXX): in theory this flake could support aarch64-linux,
      #   x86_64-darwin and aarch64-darwin, but it is untested.
      systems = [ "x86_64-linux" ];
      perSystem = { config, self', pkgs, lib, system, ... }:
        let
          buildToolsVersion = "30.0.3";
          platformVersion = "33";
          rustTargets = [ "${system}-android" ];
          abi = (lib.systems.elaborate system).linuxArch;

          devDeps = with pkgs; [
            android-sdk
            android-studio
            maven
            jdk11 # Matched to CI setup-java task's java-version
            der-ascii
          ];

          android-comp = pkgs.androidenv.composeAndroidPackages {
            buildToolsVersions = [ buildToolsVersion ];
            platformVersions = [ platformVersion ];
            abiVersions = [ abi ];

            # Note: Pinned presently to NDK 23 specifically to workaround an issue
            # with the bundled clang missing libc++ in NDK 24. We can't use NDK
            # 22, as it's too old for cargo-ndk.
            ndkVersion = "23.1.7779620";

            systemImageTypes = [ "default" ];

            includeNDK = true;
            includeEmulator = true;
            includeSystemImages = true;
          };

          # Note: additional flags can be provided to emulator through
          #   the $NIX_ANDROID_EMULATOR_FLAGS env var.
          android-emu = pkgs.androidenv.emulateApp {
            name = "emulate-PlatformVerifier";
            platformVersion = platformVersion;
            abiVersion = abi;
            systemImageType = "default";

            # Note: Depending on your hardware you may wish to enable or disable
            # this option.
            enableGPU = false;
          };

          android-sdk = android-comp.androidsdk;
          android-sdk-root = "${android-sdk}/libexec/android-sdk";

          verifierCargoToml = builtins.fromTOML
            (builtins.readFile ./rustls-platform-verifier/Cargo.toml);
          msrv = verifierCargoToml.package.rust-version;

          verifierPackage = features:
            (pkgs.makeRustPlatform {
              cargo = pkgs.rust-bin.stable.latest.minimal;
              rustc = pkgs.rust-bin.stable.latest.minimal;
            }).buildRustPackage {
              inherit (verifierCargoToml.package) name version;
              src = ./.;
              buildAndTestSubdir = "rustls-platform-verifier";
              cargoLock.lockFile = ./Cargo.lock;
              buildFeatures = features;
              doCheck = false; # Some tests require networking
            };

          mkDevShell = rustc:
            pkgs.mkShell {
              ANDROID_HOME = "${android-sdk-root}";
              ANDROID_SDK_ROOT = "${android-sdk-root}";
              ANDROID_NDK_ROOT = "${android-sdk-root}/ndk-bundle";
              JAVA_HOME = "${pkgs.jdk11}";
              # Note: It's important to set this so that gradle uses the correct
              #   aapt2 binary.
              GRADLE_OPTS =
                "-Dorg.gradle.project.android.aapt2FromMavenOverride=${android-sdk-root}/build-tools/${buildToolsVersion}/aapt2";
              shellHook = ''
                export RUST_SRC_PATH=${pkgs.rustPlatform.rustLibSrc}
                echo 1>&2 "🔒🔍 rustls-platform-verifier"
              '';
              nativeBuildInputs = devDeps ++ [ rustc ];
            };

        in {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ (import inputs.rust-overlay) ];
            config = {
              # Allow unfree packages and agree to the Android SDK terms of service.
              # Review https://developer.android.com/studio/terms before use.
              allowUnfree = true;
              android_sdk.accept_license = true;
            };
          };

          # Base library.
          packages.rustls-platform-verifier = (verifierPackage [ ]);
          # Library with debug extras.
          packages.rustls-platform-verifier-dbg =
            (verifierPackage [ "dbg" "base64" "docsrs" ]);
          # Test emulator.
          packages.android-emu = android-emu;
          packages.default = self'.packages.rustls-platform-verifier;

          devShells.nightly = (mkDevShell (pkgs.rust-bin.selectLatestNightlyWith
            (toolchain:
              toolchain.default.override { targets = rustTargets; })));
          devShells.stable = (mkDevShell
            (pkgs.rust-bin.stable.latest.default.override {
              targets = rustTargets;
            }));
          devShells.msrv = (mkDevShell
            (pkgs.rust-bin.stable.${msrv}.default.override {
              targets = rustTargets;
            }));
          devShells.default = self'.devShells.nightly;
        };
    };
}
