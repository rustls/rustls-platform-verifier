#!/usr/bin/env bash

# This script's purpose is to verify that no test-only code is present inside of the release-mode Android artifact.
# It is validating that `javac` is performing the dead-code elimiation we expect and that `proguard` is deleting the
# unreferenced test code. This can be ran both locally and in CI.
#
# It accomplishes this goal by building the artifact and then running a decompiler on it to look for names we expect or do not.

set -euo pipefail

mkdir -p ./android/verification

pushd ./android/

./gradlew clean
./gradlew assembleRelease

pushd ./verification

if [ ! -f "./bin/jadx" ]; then
    echo "Decompiler not yet installed, downloading jadx"
    curl -L https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip --output jadx.zip
    unzip jadx.zip
    echo "jadx downloaded"
fi

./bin/jadx -d decompiled ../rustls-platform-verifier/build/outputs/aar/rustls-platform-verifier-release.aar

if grep -r -q "mock" ./decompiled; then
    echo "❌ Test-only code exists in release artifact! Please review changes made to locate the cause".
    exit 1
else 
    echo "✅ No test-only code found in release artifact"
fi

if grep -r -q "verifyCertificateChain" ./decompiled; then
    echo "✅ JNI entrypoint present in release artifact"
else 
    echo "❌ JNI entrypoint not found in release artifact! Please review changes made to optimization rules which might cause this"
    exit 1
fi
