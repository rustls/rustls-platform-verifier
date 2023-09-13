package org.rustls.platformverifier

import android.annotation.SuppressLint
import android.content.Context
import android.net.http.X509TrustManagerExtensions
import android.os.Build
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.File
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CertificateParsingException
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXRevocationChecker
import java.security.cert.X509Certificate
import java.util.Date
import java.util.EnumSet
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

// If this is updated, update the Rust definition too.
// Marked private as this is not meant to be used in Android code.
private enum class StatusCode(val value: Int) {
    Ok(0),
    Unavailable(1),
    Expired(2),
    UnknownCert(3),
    Revoked(4),
    InvalidEncoding(5),
    InvalidExtension(6),
}

// Marked private as this is not meant to be used in Android code.
private class VerificationResult(
    status: StatusCode,
    @Suppress("unused") val message: String? = null
) {
    @Suppress("unused")
    private val code: Int = status.value
}

// NOTE: All TrustManager and certificate validation methods are not thread safe. These
// are all guarded by Kotlin's `Synchronized` accessors to prevent undefined behavior.

// Only JNI and test code calls this, so unused code warnings are suppressed.
// Internal for test code - no other Kotlin code should use this object directly.
@Suppress("unused")
// We want to show a difference between Kotlin-side logs and those in Rust code
@SuppressLint("LongLogTag")
internal object CertificateVerifier {
    private const val TAG = "rustls-platform-verifier-android"

    private fun createTrustManager(keystore: KeyStore?): X509TrustManagerExtensions? {
        // This can never throw since the default algorithm is used.
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())

        factory.init(keystore)

        val availableTrustManagers = try {
            factory.trustManagers
        } catch (e: RuntimeException) {
            Log.w(TAG, "exception thrown creating a TrustManager: $e")
            return null
        }

        for (manager in availableTrustManagers) {
            if (manager is X509TrustManager) {
                // Kotlin ensures this can't throw at runtime since it knows that
                // it must be the correct type by now.
                return X509TrustManagerExtensions(manager)
            }
        }

        Log.e(TAG, "failed to find a usable trust manager")
        return null
    }

    private fun makeLazyTrustManager(keystore: KeyStore?): Lazy<X509TrustManagerExtensions?> {
        // Ensure the keystore is loaded. Since all of the trust managers are initialized in a
        // `Lazy`, this will only run once.
        keystore?.load(null)

        return lazy { createTrustManager(keystore) }
    }

    // -- Test only --
    // Ideally, all of this will be optimized out at compile time due to not being accessed
    // in release builds.

    @get:Synchronized
    private val mockKeystore: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType())

    @get:Synchronized
    private var mockTrustManager: Lazy<X509TrustManagerExtensions?> =
        makeLazyTrustManager(mockKeystore)

    @JvmStatic
    private fun addMockRoot(root: ByteArray) {
        if (!BuildConfig.TEST) {
            throw Exception("attempted to add a mock root outside a test!")
        }

        val alias = "root_${mockKeystore.size()}"
        // Throwing here is fine since test roots should always be well-formed
        val cert = certFactory.generateCertificate(ByteArrayInputStream(root))
        mockKeystore.setCertificateEntry(alias, cert)

        reloadMockData()
    }

    @JvmStatic
    private fun clearMockRoots() {
        // Reload to get a completely fresh internal state
        mockKeystore.load(null)
        reloadMockData()
    }

    @JvmStatic
    private fun reloadMockData() {
        if (mockTrustManager.isInitialized()) {
            mockTrustManager = makeLazyTrustManager(mockKeystore)
        }
    }

    // Get a list of the system's root CAs.
    // Function is public for testing only.
    @JvmStatic
    fun getSystemRootCAs(): List<X509Certificate> {
        val rootCAs = mutableListOf<X509Certificate>()

        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(systemKeystore)

        val availableTrustManagers = try {
            factory.trustManagers
        } catch (e: RuntimeException) {
            Log.w(TAG, "exception thrown creating a TrustManager: $e")
            return rootCAs
        }

        availableTrustManagers.forEach { trustManager ->
            if (trustManager is X509TrustManager) {
                rootCAs.addAll(trustManager.acceptedIssuers)
            }
        }

        return rootCAs
    }

    // -- End testing requirements --

    private val certFactory: CertificateFactory = CertificateFactory.getInstance("X.509")

    private var systemTrustAnchorCache = hashSetOf<Pair<X500Principal, PublicKey>>()

    @get:Synchronized
    private var systemCertificateDirectory: File? = System.getenv("ANDROID_ROOT")?.let { rootPath ->
        File("$rootPath/etc/security/cacerts")
    }

    @get:Synchronized
    private val systemKeystore: KeyStore? = try {
        KeyStore.getInstance("AndroidCAStore")
    } catch (_: KeyStoreException) {
        null
    }

    @get:Synchronized
    private val systemTrustManager: Lazy<X509TrustManagerExtensions?> =
        makeLazyTrustManager(systemKeystore)

    @JvmStatic
    private fun verifyCertificateChain(
        @Suppress("UNUSED_PARAMETER") context: Context,
        serverName: String,
        authMethod: String,
        allowedEkus: Array<String>,
        ocspResponse: ByteArray?,
        time: Long,
        certChain: Array<ByteArray>
    ): VerificationResult {
        // Convert the array of (supposedly) DER bytes into certificates.
        val certificateChain = mutableListOf<X509Certificate>()
        certChain.forEach { certBytes ->
            val certificate = try {
                certFactory.generateCertificate(ByteArrayInputStream(certBytes))
            } catch (e: CertificateException) {
                return VerificationResult(StatusCode.InvalidEncoding)
            }
            certificateChain.add(certificate as X509Certificate)
        }

        // Will never throw `ArrayIndexOutOfBoundsException` because `rustls`'s `ServerCertVerifier` trait
        // has a mandatory `end_entity` parameter in `verify_server_cert`.
        val endEntity = certificateChain[0]

        // Check that the certificate is valid at the point of time provided by `rustls`.
        try {
            endEntity.checkValidity(Date(time))
        } catch (e: CertificateExpiredException) {
            return VerificationResult(StatusCode.Expired)
        } catch (e: CertificateNotYetValidException) {
            return VerificationResult(StatusCode.Expired)
        }

        // Check that this certificate can be used in a TLS server.
        if (!verifyCertUsage(endEntity, allowedEkus)) {
            return VerificationResult(StatusCode.InvalidExtension)
        }

        // Select the trust manager to use.
        //
        // We select them as follows:
        // - If built for release, only use the system trust manager. This should let all test-related
        // code be optimized out.
        // - If built for tests:
        //      - If the mock CA store has any values, use the mock trust manager.
        //      - Otherwise, use the system trust manager.
        val (trustManager, keystore) = if (!BuildConfig.TEST) {
            val trustManager =
                systemTrustManager.value ?: return VerificationResult(StatusCode.Unavailable)
            Pair(trustManager, systemKeystore)
        } else {
            if (mockKeystore.size() != 0) {
                val trustManager = mockTrustManager.value!!
                Pair(trustManager, mockKeystore)
            } else {
                val trustManager =
                    systemTrustManager.value ?: return VerificationResult(StatusCode.Unavailable)
                Pair(trustManager, systemKeystore)
            }
        }

        // Verify that the certificate chain is valid and correct, and nothing more.
        //
        // NOTE: This does not validate `serverName` is valid for the end-entity certificate.
        // That is handled in Rust as Android/Java do not currently provide a RFC 6125 compliant
        // hostname verifier. Additionally, even the RFC 2818 verifier is not available until API 24.
        //
        // `serverName` is only used for pinning/CT requirements.
        //
        // Returns the "the properly ordered chain used for verification as a list of X509Certificates.",
        // meaning a list from end-entity certificate to trust-anchor.
        val validChain = try {
            trustManager.checkServerTrusted(certificateChain.toTypedArray(), authMethod, serverName)
        } catch (e: CertificateException) {
            return VerificationResult(StatusCode.UnknownCert, e.toString())
        }

        // TEST ONLY: Mock test suite cannot attempt to check revocation status if no OSCP data has been stapled,
        // because Android requires certificates to an specify OCSP responder for network fetch in this case.
        // If in testing w/o OCSP stapled, short-circuit here - only prior checks apply.
        if (BuildConfig.TEST && (mockKeystore.size() != 0) && (ocspResponse == null)) {
            return VerificationResult(StatusCode.Ok)
        }

        // Try to check the revocation status of the cert, if it is supported.
        //
        // This is supported at >= API 24, but we're supporting 22 (Android 5) for the best
        // compatibility.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val parameters = PKIXBuilderParameters(keystore, null)
            val validator = CertPathValidator.getInstance("PKIX")
            val revocationChecker = validator.revocationChecker as PKIXRevocationChecker
            revocationChecker.options = revocationCheckerOptions(validChain, ocspResponse)

            // Use the OCSP data `rustls` provided, if present.
            // Its expected that the server only sends revocation data for its own leaf certificate.
            //
            // If this field is set, then Android will use it and skip any networking to
            // attempt a fetch for that certificate. Otherwise, it will attempt to fetch it from the network.
            // Ref: https://cs.android.com/android/platform/superproject/+/master:libcore/ojluni/src/main/java/sun/security/provider/certpath/RevocationChecker.java;l=694
            ocspResponse?.let { providedResponse ->
                revocationChecker.ocspResponses = mapOf(endEntity to providedResponse)
            }

            // Use the custom revocation definition.
            // "Note that when a `PKIXRevocationChecker` is added to `PKIXParameters`, it clones the `PKIXRevocationChecker`;
            // thus any subsequent modifications to the `PKIXRevocationChecker` have no effect."
            //  - https://developer.android.com/reference/java/security/cert/PKIXRevocationChecker
            parameters.certPathCheckers = listOf(revocationChecker)
            // "When supplying a revocation checker in this manner, it will be used to check revocation
            // irrespective of the setting of the `RevocationEnabled` flag."
            //  - https://developer.android.com/reference/java/security/cert/PKIXRevocationChecker
            parameters.isRevocationEnabled = false

            // Validate the revocation status of all non-root certificates in the chain.
            try {
                // `checkServerTrusted` always returns a trusted full chain. However, root CAs
                // don't have revocation properties so attempting to validate them as such fails.
                // To avoid this, always remove the root CA from the chain before validating
                // revocation status. This is identical to the `CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`
                // flag in the Win32 API.
                validChain.removeLast()
                validator.validate(certFactory.generateCertPath(validChain), parameters)
            } catch (e: CertPathValidatorException) {
                return VerificationResult(StatusCode.Revoked, e.toString())
            }
        } else {
            // This is allowed to be skipped since revocation checking is best-effort.
            Log.w(TAG, "did not attempt to validate OCSP due to Android version")
        }

        return VerificationResult(StatusCode.Ok)
    }

    private fun verifyCertUsage(certificate: X509Certificate, allowedEkus: Array<String>): Boolean {
        val ekus = try {
            certificate.extendedKeyUsage
        }
        // This should be unreachable, but could happen.
        catch (_: CertificateParsingException) {
            return false
        } catch (_: NullPointerException) {
            // According to Chromium's implementation, this can crash when the EKU data is malformed.
            Log.w(TAG, "exception handling certificate EKU")
            return false
        } ?: return true // If the list is empty, we have nothing to do.

        return ekus.any { allowedEkus.contains(it) }
    }

    // Android hashes a principal using the first four bytes of its MD5 digest, encoded in
    // lowercase hex and reversed.
    //
    // Ref: https://source.chromium.org/chromium/chromium/src/+/main:net/android/java/src/org/chromium/net/X509Util.java;l=339
    private fun hashPrincipal(principal: X500Principal): String {
        val hexDigits = "0123456789abcdef".toCharArray()
        val digest = MessageDigest.getInstance("MD5").digest(principal.encoded)
        val hexChars = CharArray(8)

        for (i in 0..3) {
            // Kotlin doesn't support bitwise operators for bytes, only Int and Long.
            val digestByte = digest[3 - i].toInt()
            hexChars[2 * i] = hexDigits[(digestByte shr 4) and 0xf]
            hexChars[2 * i + 1] = hexDigits[digestByte and 0xf]
        }

        return String(hexChars)
    }

    // Check if CA root is known or not.
    // Known means installed in root CA store, either a preset public CA or  a custom one installed by an enterprise.
    // Function is public for testing only.
    //
    // Ref: https://source.chromium.org/chromium/chromium/src/+/main:net/android/java/src/org/chromium/net/X509Util.java;l=351
    fun isKnownRoot(root: X509Certificate): Boolean {
        // System keystore and cert directory must be non-null to perform checking
        systemKeystore?.let { loadedSystemKeystore ->
            systemCertificateDirectory?.let { loadedSystemCertificateDirectory ->

                // Check the in-memory cache first
                val key = Pair(root.subjectX500Principal, root.publicKey)
                if (systemTrustAnchorCache.contains(key)) {
                    return true
                }

                // System trust anchors are stored under a hash of the principal.
                // In case of collisions, append number.
                val hash = hashPrincipal(root.subjectX500Principal)
                var i = 0
                while (true) {
                    val alias = "$hash.$i"

                    if (!File(loadedSystemCertificateDirectory, alias).exists()) {
                        break
                    }

                    val anchor = loadedSystemKeystore.getCertificate("system:$alias")

                    // It's possible for `anchor` to be `null` if the user deleted a trust anchor.
                    // Continue iterating as there may be further collisions after the deleted anchor.
                    if (anchor == null) {
                        continue
                        // This should never happen
                    } else if (anchor !is X509Certificate) {
                        // SAFETY: This logs a unique identifier (hash value) only in cases where a file within the
                        // system's root trust store is not a valid X509 certificate (extremely unlikely error).
                        // The hash doesn't tell us any sensitive information about the invalid cert or reveal any of
                        // its contents - it just lets us ID the bad file if a customer is having TLS failure issues.
                        Log.e(TAG, "anchor is not a certificate, alias: $alias")
                        continue
                        // If subject and public key match, it's a system root.
                    } else {
                        if ((root.subjectX500Principal == anchor.subjectX500Principal) && (root.publicKey == anchor.publicKey)) {
                            systemTrustAnchorCache.add(key)
                            return true
                        }
                    }

                    i += 1
                }
            }
        }

        // Not found in cache or store: non-public
        return false
    }

    // Returns true if all certificates in the provided list contain an X.509v3 Authority Information
    // Access (AIA) extension with a OCSP access method and location URI.
    private fun chainHasAiaOcspUris(certs: List<X509Certificate>): Boolean {
        return certs.all { certHasAiaOcspUri(it) }
    }

    // Returns true if the provided certificate contains an X.509v3 Authority Information Access
    // (AIA) extension with an OCSP access method and location URI. See RFC 5280 Section 4.2.2.1[0]
    // for more information.
    //
    // [0]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1
    private fun certHasAiaOcspUri(cert: X509Certificate): Boolean {
        // Retrieve the raw Authority Information Access (AIA) extension DER value by OID.
        //
        //   id-pkix OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
        //                                 dod(6) internet(1) security(5) mechanisms(5) pkix(7) }
        //   id-pe  OBJECT IDENTIFIER  ::=  { id-pkix 1 }
        //   id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
        val oidIdPeAuthorityInfoAccess = "1.3.6.1.5.5.7.1.1"; // { id-pe 1 }
        val rawAiaExt = cert.getExtensionValue(oidIdPeAuthorityInfoAccess) ?: return false

        // Because Java/Android do not expose the OCSP provider code used to parse the AIA extension,
        // or offer facilities for general DER parsing, we try to find the pre-encoded DER representation
        // of the id-ad-ocsp OID used to specify an OCSP accessMethod in the raw extension.
        //
        //   id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
        //   id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
        //
        // For a description of OID encoding, see this Microsoft[0] documentation.
        // [0]: https://learn.microsoft.com/en-ca/windows/win32/seccertenroll/about-object-identifier
        //
        // Note: it is safe to use a byte array of _signed_ byte values here because all values are
        //       less than 0x80 (128).
        val ocspIdAdOcsp = byteArrayOf(
            0x06, // OBJECT IDENTIFIER Tag
            0x08, // Short-form encoded length
            0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01 // 0x8 bytes of encoded id-ad-ocsp OID
        )

        // If the raw extension is empty, or smaller than the encoding of ocspIdAdOcsp there's
        // no point trying to search for ocspIdAdOcsp.
        if (rawAiaExt.isEmpty() || rawAiaExt.size < ocspIdAdOcsp.size) {
            return false
        }

        // Search byte-by-byte for a match of the entire ocspIdAdOcsp byteArray within the
        // rawAiaExt byteArray.
        var offset = 0
        var matchOffset = 0
        while (rawAiaExt.size - offset > ocspIdAdOcsp.size - 1) {
            if (rawAiaExt[offset] == ocspIdAdOcsp[matchOffset]) {
                // We have found the ocspIdAdOcsp bytes in the rawAiaExt.
                if (++matchOffset == ocspIdAdOcsp.size) {
                    return true
                }
            } else {
                matchOffset = 0
            }
            offset++
        }

        // We did not find the ocspIdAdOcsp bytes in the rawAiaExt.
        return false
    }

    // Build a set of PKIXRevocationChecker.Option revocation options for the given chain of
    // certificates, and an optional end-entity OCSP response.
    //
    // Note: Requires Build.VERSION_CODES.N or higher.
    private fun revocationCheckerOptions(validChain: List<X509Certificate>, ocspResponse: ByteArray?): EnumSet<PKIXRevocationChecker.Option> {
        // validChain as returned from the system TrustManager is a list from end-entity to root trust anchor.
        // It should never be the case that we get a chain that has less than two certificates.
        if (validChain.size < 2) {
            throw IllegalArgumentException()
        }
        val endEntity = validChain[0]
        val root = validChain[validChain.size - 1]
        val intermediates = if (validChain.size > 2) validChain.subList(1, validChain.size - 1) else listOf()

        // 1. Android does not provide any way only to attempt to validate revocation from cached
        // data like the other platforms do. This means it will always use the network for
        // certificates which had no stapled response.
        //
        // 2: Likely because of 1, Android requires all issued certificates to have some form of
        // revocation included in their authority information. This doesn't work universally as
        // internal CAs managed by companies aren't required to follow this (and generally don't),
        // so verifying those certificates would fail.
        //
        // The options we use for revocation checking therefore have a few input factors:
        //
        // 1. Is the root CA known (installed in system trust store)?
        // 2. Does the entire chain have OCSP AIA information?
        // 3. Does the end-entity certificate have OCSP AIA information?
        // 4. Did the server staple an OCSP response for the end-entity certificate?
        val rootKnown = isKnownRoot(root)
        val intermediatesHaveAiaOcspUri = chainHasAiaOcspUris(intermediates)
        val endEntityHasAiaOcspUri = certHasAiaOcspUri(endEntity)
        val hasOcspStaple = ocspResponse != null

        // TODO(@cpu): Remove logs after debugging done? >:)
        Log.d(TAG, "root is known? $rootKnown")
        Log.d(TAG, "intermediates have AIA OCSP URIs? $intermediatesHaveAiaOcspUri")
        Log.d(TAG, "endEntity has AIA OCSP URI? $endEntityHasAiaOcspUri")
        Log.d(TAG, "endEntity has stapled OCSP resp? $hasOcspStaple")

        // By default, `PKIXRevocationChecker` checks the entire chain
        // (because "ONLY_END_ENTITY" is not present), and prefers OCSP (because the private
        // variant "PREFER_OCSP" is present).
        // Ref: https://cs.android.com/android/platform/superproject/+/master:libcore/ojluni/src/main/java/sun/security/provider/certpath/RevocationChecker.java;l=76;drc=62fc99a7a5bdf55bdea3383f29b9997948683730
        //
        // We extend the defaults to allow revocation checking to succeed for the
        // soft fail errors outlined in the reference docs (network errors, or particular OCSP
        // response codes).
        // Ref: https://developer.android.com/reference/java/security/cert/PKIXRevocationChecker.Option#SOFT_FAIL
        val revocationOptions = EnumSet.of(PKIXRevocationChecker.Option.SOFT_FAIL)

        // First, we must determine if we will check the entire chain, or just the end-entity.
        if (!rootKnown) {
            // If the root is not known, only check revocation status for the end-entity.
            revocationOptions.add(PKIXRevocationChecker.Option.ONLY_END_ENTITY)
        } else if (!intermediatesHaveAiaOcspUri && (hasOcspStaple || endEntityHasAiaOcspUri)) {
            // If the intermediate certificates don't all have AIA OCSP URIs, but we have an OCSP
            // staple for the end-entity, or the end-entity has an AIA OCSP URL, then only validate
            // the end entity.
            revocationOptions.add(PKIXRevocationChecker.Option.ONLY_END_ENTITY)
        }
        // In all other cases we default to checking the entire chain.

        // Next, we must determine if we will prefer OCSP and fall back to CRLs, or if
        // we should prefer CRLS and not fall back because we known OCSP checking will fail.
        if (revocationOptions.contains(PKIXRevocationChecker.Option.ONLY_END_ENTITY)) {
            // If we're only checking the end entity, the decision is simple:
            // do we have a staple or AIA for the end-entity? If not, prefer CRL w/o fall
            // back.
            if (!hasOcspStaple && !endEntityHasAiaOcspUri) {
                revocationOptions.add(PKIXRevocationChecker.Option.PREFER_CRLS)
                revocationOptions.add(PKIXRevocationChecker.Option.NO_FALLBACK)
            }
        } else {
            // If we're checking the entire chain, but don't have revocation information
            // for the whole chain, we must prefer CRLs and not fall back to OCSP.
            if (!intermediatesHaveAiaOcspUri || (!hasOcspStaple && !endEntityHasAiaOcspUri)) {
                revocationOptions.add(PKIXRevocationChecker.Option.PREFER_CRLS)
                revocationOptions.add(PKIXRevocationChecker.Option.NO_FALLBACK)
            }
        }
        // In all other cases we'll prefer OCSP and fall-back to CRLS.

        // TODO(@cpu): Remove log after debugging done? >:)
        Log.d(TAG, "revocation checker options: $revocationOptions")

        return revocationOptions
    }
}
