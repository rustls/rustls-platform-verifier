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
    1. Update Android artifact version in `android-release-support/Cargo.toml`, and in the main crate if creating an incompatible SemVer release.
    2. Commit version increase changes on the release branch
        * We typically name these branches `rel-xxx` where `xxx` is the major version.
        * We typically leave these branches around for future maintenance releases.
    3. Run `ci/package_android_release.sh` in a UNIX compatible shell
    4. Commit the Maven metadata updates on their own: `git commit -am "Bump Maven release to x.x.x"`. Copy the new commit's short ID.
    5. **Ensure that all version changes are committed to the correct branch before proceeding**. All version increases should be checked in prior
       to publishing on crates.io.
    6. Checkout the Maven storage branch: `git checkout maven-archive`. The newly built artifacts are now ready to check in.
    7. Add the new artifacts to storage: `git add . && git commit -m "Prepare Maven release x.x.x"`
    8. Sync the Maven metadata to make the new artifacts visible: `git cherry-pick $MAVEN_BUMP_COMMIT_ID`
    9. Publish the new changes:
        * `git push && git checkout rel-xxx`
        * Publish the new Android marker version: `cargo publish -p rustls-platform-verifier-android`

3. Commit main crate's version increase on the release branch
4. **Ensure that all version changes are committed to the correct branch before proceeding**. All version increases should be checked in prior
    to publishing on crates.io.
5. Publish the main crate's new version: `cargo publish -p rustls-platform-verifier`
6. Follow the remaining steps in [RELEASING] to create the appropiate version tag.

[RELEASING]: https://github.com/rustls/rustls/blob/main/RELEASING.md
