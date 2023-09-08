#!/usr/bin/env bash

# This script's purpose is to automate the build + packaging steps for the pre-compiled Android verifier component.
# It works with template files and directories inside the `android-release-support/` part of the repository to setup
# a Maven local repository and then add the pre-compiled AAR file into it for distribution. The results of this packaging
# are then included by `cargo` when publishing `rustls-platform-verifier-android`.

set -euo pipefail

if ! type mvn > /dev/null; then
  echo "The maven CLI, mvn, is required to run this script."
  echo "Download it from: https://maven.apache.org/download.cgi"
  exit 1
fi

version=$(cat android-release-support/Cargo.toml | grep -m 1 "version = " | tr -d "version= " | tr -d '"')

echo "Packaging v$version of the Android support component"

pushd ./android

./gradlew assembleRelease

popd

artifact_name="rustls-platform-verifier-release.aar"

pushd ./android-release-support

artifact_path="../android/rustls-platform-verifier/build/outputs/aar/$artifact_name"

# Ensure no prior artifacts are present
git clean -dfX "./maven/"

cp ./pom-template.xml ./maven/pom.xml
sed -i "" "s/\$VERSION/$version/" ./maven/pom.xml

mvn install:install-file -Dfile="$artifact_path" -Dpackaging="aar" -DpomFile="./maven/pom.xml" -DlocalRepositoryPath="./maven/"
