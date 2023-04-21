# rustls-platform-verifier

[![crates.io version](https://img.shields.io/crates/v/rustls-platform-verifier.svg)](https://crates.io/crates/rustls-platform-verifier)
[![crate documentation](https://docs.rs/rustls-platform-verifier/badge.svg)](https://docs.rs/rustls-platform-verifier)
![MSRV](https://img.shields.io/badge/rustc-1.56+-blue.svg)
[![crates.io downloads](https://img.shields.io/crates/d/rustls-platform-verifier.svg)](https://crates.io/crates/rustls-platform-verifier)
![CI](https://github.com/1Password/rustls-platform-verifier/workflows/CI/badge.svg)

A Rust library to verify the validity of TLS certificates based on the operating system's certificate facilities.
On operating systems that don't have these, `webpki` and/or `rustls-native-certs` is used instead.

This crate is advantageous over `rustls-native-certs` on its own for a few reasons:
- Improved correctness and security, as the OSes [CA constraints](https://support.apple.com/en-us/HT212865) will be taken into account.
- Better integration with OS certificate stores and enterprise CA deployments.
- Revocation support via verifying validity via OCSP and CRLs.
- Less I/O and memory overhead because all the platform CAs don't need to be loaded and parsed. 

This library supports the following platforms and flows:

| OS             | Certificate Store                             | Verification Method                  | Revocation Support | 
|----------------|-----------------------------------------------|--------------------------------------|--------------------|
| Windows        | Windows platform certificate store            | Windows API certificate verification | Yes                |
| macOS (10.14+) | macOS platform roots and keychain certificate | macOS `Security.framework`           | Yes                |
| iOS            | iOS platform roots and keychain certificates  | iOS `Security.framework`             | Yes                |
| Android        | Android System Trust Store                    | Android Trust Manager                | Sometimes[^1]      |
| Linux          | webpki roots and platform certificate bundles | webpki                               | No[^2]             |
| WASM           | webpki roots                                  | webpki                               | No[^2]             |

[^1]: On Android, revocation checking requires API version >= 24 (e.g. at least Android 7.0, August 2016).
For newer devices that support revocation, Android requires certificates to specify a revocation provider
for network fetch (including optionally stapled OSCP response only applies to chain's end-entity).
This may cause revocation checking to fail for enterprise/internal CAs that don't properly issue an end-entity.

[^2]: <https://docs.rs/rustls/0.20.6/src/rustls/verify.rs.html#341>

## Installation and setup
On most platforms, no setup should be required beyond adding the dependency via `cargo`:
```toml
rustls-platform-verifier = "0.1"
```

### Android
Some manual setup is required, outside of `cargo`, to use this crate on Android. In order to
use Android's certificate verifier, the crate needs to call into the JVM. A small Kotlin
component must be included in your app's build to support `rustls-platform-verifier`.

#### Gradle Setup

`rustls-platform-verifier` bundles the required native components in the crate, but the project must be setup to locate them
automatically and correctly.

Firstly, create an [init script](https://docs.gradle.org/current/userguide/init_scripts.html) in your Android
Gradle project, with a filename of `init.gradle`. This is generally placed in your project's root. In your project's `settings.gradle`, add these lines:

```groovy
apply from: file("./init.gradle");
// Cargo automatically handles finding the downloaded crate in the correct location
// for your project.
def veifierProjectPath = findRustlsPlatformVerifierProject()
includeBuild("${verifierProjectPath}/android/")
```

Next, the `rustls-platform-verifier` external dependency needs to be setup. Open the `init.gradle` file and add the following:
`$PATH_TO_DEPENDENT_CRATE` is the relative path to the Cargo manifest (`Cargo.toml`) of any crate in your workspace that depends on `rustls-platform-verifier`
from the location of your `init.gradle` file.

Alternatively, you can use `cmdProcessBuilder.directory(File("PATH_TO_ROOT"))` to change the working directory instead.

```groovy
ext.findRustlsPlatformVerifierProject = {
    def cmdProcessBuilder = new ProcessBuilder(new String[] { "cargo", "metadata", "--format-version", "1", "--manifest-path", "$PATH_TO_DEPENDENT_CRATE" })
    def dependencyInfoText = new StringBuffer()

    def cmdProcess = cmdProcessBuilder.start()
    cmdProcess.consumeProcessOutput(dependencyInfoText, null)
    cmdProcess.waitFor()

    def dependencyJson = new groovy.json.JsonSlurper().parseText(dependencyInfoText.toString())
    def manifestPath = file(dependencyJson.packages.find { it.name == "rustls-platform-verifier" }.manifest_path)
    return manifestPath.parent
}
```

This script can be tweaked as best suits your project, but the `cargo metadata` invocation must be included so that the Android
implementation source can be located on disk.

If your project often updates its Android Gradle Plugin versions, you should additionally consider setting your app's project
up to override `rustls-platform-verifier`'s dependency versions. This allows your app to control what versions are used and avoid
conflicts. To do so, advertise a `versions.path` system property from your `settings.gradle`:

```groovy
ext.setVersionsPath = {
    System.setProperty("versions.path", file("your/versions/path.toml").absolutePath)
}

setVersionsPath()
```

Finally, sync your gradle project changes. It should pick up on the `rustls-platform-verifier` Gradle project. It should finish
successfully, resulting in a `rustls` group appearing in Android Studio's project view.
After this, everything should be ready to use. Future updates of `rustls-platform-verifier` won't need any maintenance beyond the
expected `cargo update`.

#### Crate initialization

In order for the crate to call into the JVM, it needs handles from Android. These
are provided either the `init_external` or `init_hosted` function. These give `rustls-platform-verifier`
the resources it needs to make calls into the Android certificate verifier.

As an example, if your Rust Android component which the "native" Android 
part of your app calls at startup has an initialization, like this:
```rust ,ignore
#[export_name = "Java_com_orgname_android_rust_init"]
extern "C" fn java_init(
    env: JNIEnv,
    _class: JClass,
    context: JObject,
) -> jboolean {
    // ... initialize your app's other parts here.
}
```

In the simplest case, you should to insert a call to `rustls_platform_verifier::android::init_hosted()` here, 
before any networking has a chance to run. This only needs to be called once and
the verifier will be valid for the lifetime of your app's process.

```rust ,ignore
extern "C" fn java_init(
    env: JNIEnv,
    _class: JClass,
    context: JObject,
) -> jboolean {
    // ... initialize your app's other parts here.

    // Then, initialize the certificate verifier for future use.
    rustls_platform_verifier::android::init_hosted(&env, context);
}
```

In more advanced cases, such as where your code already stores long-lived handles into 
the Android environment, you can alternatively use `init_external`. This function takes
a `&'static` reference to something that implements the `android::Runtime` trait, which the
crate then uses to obtain the access when required to the JVM.

## Credits
Made with ❤️ by the [1Password](https://1password.com/) team. Portions of the Android and Windows implementation
were adapted and referenced from Chromium's verifier implementation as well.

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>