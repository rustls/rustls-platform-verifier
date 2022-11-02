//! This build script, optionally, handles generating a local copy of the
//! `rustls-platform-verifier` Android gradle component.
//!
//! When `RUSTLS_PLATFORM_VERIFIER_GEN_ANDROID_SRC` is set, it will copy the bundled Kotlin
//! sources into `$TARGET_DIR/rustls-platform-verifier/android`.
//!
//! This must be done in a build script because `cargo` doesn't support running
//! binaries from dependency packages (outside the workspace).
#![allow(unreachable_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const ANDROID_SRC_GEN: &str = "RUSTLS_PLATFORM_VERIFIER_GEN_ANDROID_SRC";

fn main() {
    // Always rerun this script if the variable changed, regardless of the output files.
    println!("cargo:rerun-if-env-changed={}", ANDROID_SRC_GEN);

    // If Android compilation wasn't requested, exit early
    // so those not using Android don't eat the time or target
    // clutter cost.
    if env::var(ANDROID_SRC_GEN).is_err() {
        return;
    }

    let manifest_dir = std::env::current_dir().unwrap();
    let android_src = manifest_dir
        .join("android")
        .join("rustls-platform-verifier");

    // In order to have a deterministic path to declare in `build.gradle`, we
    // write the files to the parent target directory.
    let target_dir = env::var("CARGO_TARGET_DIR").map_or_else(
        |_| {
            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

            let mut target_dir = None;
            for dir in out_dir.ancestors() {
                if dir.ends_with("target") {
                    target_dir = Some(dir.to_path_buf())
                }
            }

            target_dir.expect("no target dir found")
        },
        PathBuf::from,
    );

    let dest = target_dir.join("rustls-platform-verifier").join("android");

    fs::create_dir_all(&dest).unwrap();
    copy_dir(&android_src, &dest);
}

fn copy_dir(src: &Path, dest: &Path) {
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();

        let path = entry.path();
        let filename = path.file_name().unwrap();

        let dest = dest.join(filename);

        if entry.file_type().unwrap().is_dir() {
            // Skip any build artifacts that might be present.
            if filename == "build" {
                continue;
            }

            fs::create_dir_all(&dest).unwrap();
            copy_dir(&path, &dest);
        } else {
            let _ = fs::remove_file(&dest);
            fs::copy(&path, &dest).unwrap();
        }
    }
}
