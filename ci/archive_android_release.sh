#!/usr/bin/env bash

# This script's purpose is to package up the Android-specific artifacts from a previous run of `cargo publish -p rustls-platform-verifier-android` for
# later attachment to GitHub releases. It is also intended to be fully reproducible.

set -euo pipefail

TAR_NAME="tar"
OUTPUT_NAME="android-artifacts.tar"
version=$(grep -m 1 "version = " android-release-support/Cargo.toml | tr -d "version= " | tr -d '"')
source_date_epoch=$(git log -1 --pretty=%ct)

# bsdtar (which is the default on macOS) doesn't support the flags we want, so attempt to find a version of GNU
# tar on the system is possible.
if $TAR_NAME --version | grep -q "bsdtar"; then
    echo "Detected bsdtar, which is not compatible with this script. Attempting 'gnutar'"
    TAR_NAME="gnutar"

    if $TAR_NAME --version | grep -q "bsdtar"; then
        echo "GNU tar not found, exiting"
        exit 1
    fi
fi

artifacts_dir="target/package/rustls-platform-verifier-android-$version"

# This differs based on host target, etc.
rm -rf "$artifacts_dir/target"
# This shows up a lot on macOS, so make sure it doesn't get in the way.
rm -f "$artifacts_dir/.DS_Store"

# Ref: https://reproducible-builds.org/docs/archives/
$TAR_NAME --sort=name \
    --mtime="@${source_date_epoch}" \
    --owner=0 --group=0 --numeric-owner \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -cf "$artifacts_dir/../$OUTPUT_NAME" -C "$artifacts_dir" .

echo "Successfully created tarball at $artifacts_dir/$OUTPUT_NAME"
