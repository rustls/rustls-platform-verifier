# How-to release `rustls-platform-verifier`

This document records the steps to publish new versions of the crate since it requires non-trivial preperation and ordering
that needs to be remembered due to the Android component's distribution.

## Steps

1. Update main crate'a version in `rustls-platform-verifier/Cargo.toml`, and in any additional places.
2. If any non-test changes have been made to the `android` directory since the last release:
    1. Update Android artifact version in `android-release-support/Cargo.toml`
    2. Bump dependency version of the Android support crate in `rustls-platform-verifier/Cargo.toml` to match the new one
    3. Commit version increase changes on the release branch
    4. Run `ci/package_android_release.sh` in a UNIX compatible shell
    5. (Optional) `cargo publish -p rustls-platform-verifier-android --dry-run`
    6. (Optional) Inspect extracted archive to ensure the local Maven repository artifacts are present
    7. Publish the Android artifacts' new version: `cargo publish -p rustls-platform-verifier-android`
3. Commit main crate's version increase on the release branch
4. Publish the main crate's new version: `cargo publish -p rustls-platform-verifier`
