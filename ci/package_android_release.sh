#!/usr/bin/env bash

# This script's purpose is to automate the build + packaging steps for the pre-compiled Android verifier component.
# It works with template files and directories inside the `android-release-support/` part of the repository to setup
# a Maven local repository and then add the pre-compiled AAR file into it for distribution. The results of this packaging
# are then published to dedicated artifacts Git branch on GitHub, emulating an actual online Mavan package repository.
#
# Gradle and other clients download the artifacts from thier native build systems later on with the requested files lining up
# with the structure of the Git repo's contents. This idea was originally inspired by https://github.com/RiV-chain/github-publish-maven-action.

set -euo pipefail

if ! type mvn > /dev/null; then
  echo "The maven CLI, mvn, is required to run this script."
  echo "Download it from: https://maven.apache.org/download.cgi"
  exit 1
fi

version=$(grep -m 1 "version = " android-release-support/Cargo.toml | tr -d "version= " | tr -d '"')

echo "Packaging v$version of the Android support component"

pushd ./android

./gradlew assembleRelease

popd

package_name="rustls-platform-verifier"

artifact_name="$package_name-release.aar"

pushd ./android-release-support

artifact_path="../android/$package_name/build/outputs/aar/$artifact_name"

cp ./pom-template.xml ./maven/pom.xml

# This sequence is meant to workaround the incompatibilites between macOS's sed
# command and the GNU command. Referenced from the following:
# https://stackoverflow.com/questions/5694228/sed-in-place-flag-that-works-both-on-mac-bsd-and-linux
sed -i.bak "s/\$VERSION/$version/" ./maven/pom.xml
rm ./maven/pom.xml.bak

mvn install:install-file -Dfile="$artifact_path" -Dpackaging="aar" -DpomFile="./maven/pom.xml" -DlocalRepositoryPath="./maven/"

rm ./maven/pom.xml

pushd ./maven/

artifacts_folder="org/rustls/$package_name/$version"

rm "$artifacts_folder/_remote.repositories"

sha1sum "$artifacts_folder/$package_name-$version.aar" > "$artifacts_folder/$package_name-$version.aar.sha1"
sha1sum "$artifacts_folder/$package_name-$version.pom" > "$artifacts_folder/$package_name-$version.pom.sha1"

