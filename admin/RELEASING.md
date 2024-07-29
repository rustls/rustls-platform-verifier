# How-to release `rustls-platform-verifier`

This document records the steps to publish new versions of the crate since it requires non-trivial preparation and ordering
that needs to be accounted for due to the Android component's distribution.

The Rustls repo also has [RELEASING] guidance for more information (e.g. on best practices for creating a GitHub release with a changelog)
and other steps.

In the release preparation PR, the releaser may include the following checklist in the description so post-merge actions can be tracked:
```markdown
### Post-merge steps

- [ ] Generate Android Maven artifacts locally
- [ ] Create and push Git tag
- [ ] `cargo publish` for each required crate, based on release steps
- [ ] Create companion GitHub release
```

## Steps

1. Update main crate's version in `rustls-platform-verifier/Cargo.toml`.
2. If any non-test changes have been made to the `android` directory since the last release:
    1. Update Android artifact version in `android-release-support/Cargo.toml`
    2. Bump dependency version of the Android support crate in `rustls-platform-verifier/Cargo.toml` to match the new one
    3. Commit version increase changes on the release branch
        * We typically name these branches `rel-xxx` where `xxx` is the major version.
        * We typically leave these branches around for future maintenance releases.
    4. Run `ci/package_android_release.sh` in a UNIX compatible shell
    5. (Optional) `cargo publish -p rustls-platform-verifier-android --dry-run --allow-dirty`
        * `--allow-dirty` is required because we don't check-in the generated Maven local repository.
    6. (Optional) Inspect extracted archive to ensure the local Maven repository artifacts are present
        1. Un-tar the `rustls-platform-verifier-android-*.crate` file inside of `target/package`.
        2. Verify `maven/rustls/rustls-platform-verifier` contains a single `*.RELEASE` directory and that contains a `.aar` file.
        3. (Optional) If the releaser has an external Gradle project that uses the configuration from the README, paste the path to the
           unzipped package's `Cargo.toml` as a replacement for the `manifestPath` variable. Run a Gradle Sync and observe everything works.
    7. **Ensure that all version changes are committed to the correct branch before proceeding**. All version increases should be checked in prior
       to publishing on crates.io.
    8. Publish the Android artifacts' new version: `cargo publish -p rustls-platform-verifier-android --allow-dirty`

3. Commit main crate's version increase on the release branch
4. **Ensure that all version changes are committed to the correct branch before proceeding**. All version increases should be checked in prior
    to publishing on crates.io.
5. Publish the main crate's new version: `cargo publish -p rustls-platform-verifier`
    * Do **not** use `--allow-dirty` for the main crate. Only the Android component requires it and a dirty workspace elsewhere is an error.
6. Follow the remaining steps in [RELEASING] to create the appropiate version tag.
7. If a new Android component release was made: Before publishing the GitHub release, run `./ci/archive_android_release.sh` to create a reproducible archive
   containing the Android Maven components that were just published to crates.io. After creating the archive, upload it as an additional release artifact on GitHub.
   Then, finish the release creation like normal.

[RELEASING]: https://github.com/rustls/rustls/blob/main/RELEASING.md
