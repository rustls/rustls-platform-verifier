# How-to release `rustls-platform-verifier`

This document records the steps to publish new versions of the crate since it requires non-trivial preparation and ordering
that needs to be remembered due to the Android component's distribution.

## Steps

1. Update main crate's version in `rustls-platform-verifier/Cargo.toml`.
2. If any non-test changes have been made to the `android` directory since the last release:
    1. Update Android artifact version in `android-release-support/Cargo.toml`
    2. Bump dependency version of the Android support crate in `rustls-platform-verifier/Cargo.toml` to match the new one
    3. Commit version increase changes on the release branch
        * We typically name these branches `rel-xxx` where `xxx` is the major version.
        * We typically leave these branches around for future maintenance releases.
    4. Run `ci/package_android_release.sh` in a UNIX compatible shell
    5. (Optional) `cargo publish -p rustls-platform-verifier-android --dry-run --alow-dirty`
        <!---
        TODO: Consider instead making tag-specific commits that check-in the artifacts. For now, the 
        seamless AAR reproducibility makes this a non-issue.
        -->
        * `--allow-dirty` is required because we don't check-in the generated Maven local repository at this time.
    6. (Optional) Inspect extracted archive to ensure the local Maven repository artifacts are present
        1. Un-tar the `rustls-platform-verifier-android-*.crate` file inside of `target/package`.
        2. Verify `maven/rustls/rustls-platform-verifier` contains a single `*.RELEASE` directory and that contains a `.aar` file.
        3. (Optional) If the releaser has an external Gradle project that uses the configuration from the README, paste the path to the
           unzipped package's `Cargo.toml` as a replacement for the `manifestPath` variable. Run a Gradle Sync and observe everything works.
    7. Publish the Android artifacts' new version: `cargo publish -p rustls-platform-verifier-android --alow-dirty`
3. Commit main crate's version increase on the release branch
4. Publish the main crate's new version: `cargo publish -p rustls-platform-verifier`
    * Do **not** use `--allow-dirty` for the main crate. Only the Android component requires it and a dirty workspace elsewhere is an error.

See the Rustls repo [RELEASING] guidance for more information (e.g. on best practices for creating a GitHub release with a changelog).

[RELEASING]: https://github.com/rustls/rustls/blob/main/RELEASING.md
