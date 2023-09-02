# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

-keepattributes SourceFile,LineNumberTable,MethodAttributes
# Everything is called via the JNI, so code must not be removed or renamed
# in a way Rust can't see.
-dontobfuscate

# We need this function (and class) in all builds for Rust to call because its the JNI entrypoint
# for the verifier functionality.
-keep class org.rustls.platformverifier.CertificateVerifier {
    verifyCertificateChain(
        android.content.Context,
        java.lang.String,
        java.lang.String,
        java.lang.String[],
        byte[],
        long,
        byte[][]
    );
}

# We need these classes so Rust can load their class definitions at runtime
# and access their fields at runtime.
-keep class org.rustls.platformverifier.StatusCode { *; }
-keep class org.rustls.platformverifier.VerificationResult { *; }

# Note: We don't explicitly tell Proguard to remove test-only methods. They are instead
# removed as dead code because `javac` removes all references to them when not building
# in a test configuration.

# This can be uncommented during development if needed to quickly check if
# a few test-only methods/fields are being removed by build time.
# -whyareyoukeeping class org.rustls.platformverifier.CertificateVerifier {
#   private java.security.KeyStore mockKeystore;
#    addMockRoot(byte[]);
#}
