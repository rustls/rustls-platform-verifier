# rustls-platform-verifier

[![crates.io version](https://img.shields.io/crates/v/rustls-platform-verifier.svg)](https://crates.io/crates/rustls-platform-verifier)
[![crate documentation](https://docs.rs/rustls-platform-verifier/badge.svg)](https://docs.rs/rustls-platform-verifier)
![MSRV](https://img.shields.io/badge/rustc-1.64+-blue.svg)
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
| Linux          | System CA bundle, or user-provided certs[^3]  | webpki                               | No[^2]             |
| WASM           | webpki roots                                  | webpki                               | No[^2]             |

[^1]: On Android, revocation checking requires API version >= 24 (e.g. at least Android 7.0, August 2016).
When available, revocation checking is only performed for the end-entity certificate. If a stapled OCSP
response for the end-entity cert isn't provided, and the certificate omits both a OCSP responder URL and
CRL distribution point to fetch revocation information from, revocation checking may fail.

[^2]: The fall-back webpki verifier configured for Linux/WASM does not support providing CRLs for revocation
checking. If you require revocation checking on these platforms, prefer constructing your own
`WebPkiServerVerifier`, providing necessary CRLs. See the Rustls [`ServerCertVerifierBuilder`] docs for more
information.

[^3]: On Linux the [rustls-native-certs] and [openssl-probe] crates are used to try and discover the system CA bundle.
Users may wish to augment these certificates with [webpki-roots] using [`Verifier::new_with_extra_roots`] in case
a system CA bundle is unavailable.

[`ServerCertVerifierBuilder`]: https://docs.rs/rustls/latest/rustls/client/struct.ServerCertVerifierBuilder.html
[`Verifier::new_with_extra_roots`]: https://docs.rs/rustls-platform-verifier/latest/rustls_platform_verifier/struct.Verifier.html#method.new_with_extra_roots
[rustls-native-certs]: https://github.com/rustls/rustls-native-certs
[openssl-probe]: https://github.com/alexcrichton/openssl-probe
[webpki-roots]: https://github.com/rustls/webpki-roots

## Installation and setup
On most platforms, no setup should be required beyond adding the dependency via `cargo`:
```toml
rustls-platform-verifier = "0.3"
```

To get a rustls `ClientConfig` configured to use the platform verifier use:

```rust
let config = rustls_platform_verifier::tls_config();
```

This crate will use the [rustls process-default crypto provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html#using-the-per-process-default-cryptoprovider). To construct a `ClientConfig` with a different `CryptoProvider`, use:

```rust
let arc_crypto_provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
let config = rustls_platform_verifier::tls_config_with_provider(arc_crypto_provider);
```

If you want to adapt the configuration, you can build the `ClientConfig` like this:

```rust
use std::sync::Arc;
use rustls::ClientConfig;
use rustls_platform_verifier::Verifier;

let mut config = ClientConfig::builder()
    .dangerous() // The `Verifier` we're using is actually safe
    .with_custom_certificate_verifier(Arc::new(Verifier::new()))
    .with_no_client_auth();
```

### Android
Some manual setup is required, outside of `cargo`, to use this crate on Android. In order to
use Android's certificate verifier, the crate needs to call into the JVM. A small Kotlin
component must be included in your app's build to support `rustls-platform-verifier`.

#### Gradle Setup

`rustls-platform-verifier` bundles the required native components in the crate, but the project must be setup to locate them
automatically and correctly. These steps assume you are using `.gradle` Groovy files because they're the most common, but everything
is 100% applicable to Kotlin script (`.gradle.kts`) configurations too with a few replacements.

Inside of your project's `build.gradle` file, add the following code and Maven repository definition. If applicable, this should only be the one "app" sub-project that
will actually be using this crate at runtime. With multiple projects running this, your Gradle configuration performance may degrade.

`$PATH_TO_DEPENDENT_CRATE` is the relative path to the Cargo manifest (`Cargo.toml`) of any crate in your workspace that depends on `rustls-platform-verifier` from
the location of your `build.gradle` file:

```groovy
import groovy.json.JsonSlurper

// ...Your own script code could be here...

repositories {
    // ... Your other repositories could be here...
    maven {
        url = findRustlsPlatformVerifierProject()
        metadataSources.artifact()
    }
}

String findRustlsPlatformVerifierProject() {
    def dependencyText = providers.exec {
        it.workingDir = new File("../")
        commandLine("cargo", "metadata", "--format-version", "1", "--manifest-path", "$PATH_TO_DEPENDENT_CRATE/Cargo.toml")
    }.standardOutput.asText.get()

    def dependencyJson = new JsonSlurper().parseText(dependencyText)
    def manifestPath = file(dependencyJson.packages.find { it.name == "rustls-platform-verifier-android" }.manifest_path)
    return new File(manifestPath.parentFile, "maven").path
}
```

Then, wherever you declare your dependencies, add the following:
```groovy
implementation "rustls:rustls-platform-verifier:latest.release"
```

Cargo automatically handles finding the downloaded crate in the correct location for your project. It also handles updating the version when
new releases of `rustls-platform-verifier` are published. If you only use published releases, no extra maintenance should be required.

These script snippets can be tweaked as best suits your project, but the `cargo metadata` invocation must be included so that the Android
implementation part can be located on-disk.

#### Proguard

If your Android application makes use of Proguard for optimizations, its important to make sure that the Android verifier component isn't optimized
out because it looks like dead code. Proguard is unable to see any JNI usage, so your rules must manually opt into keeping it. The following rule
can do this for you:
```text
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }
```

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
Made with ❤️ by the [1Password](https://1password.com/) and `rustls` teams. Portions of the Android and Windows implementation
were adapted and referenced from Chromium's previous verifier implementations as well.

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
