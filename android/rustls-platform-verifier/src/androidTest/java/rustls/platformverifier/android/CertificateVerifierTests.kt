package rustls.platformverifier.android

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

private const val SUCCESS_MARKER: String = "success"
private const val FAILURE_MSG: String = "A test failed. Check the logs above for Rust panics."

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(AndroidJUnit4::class)
class CertificateVerifierTests {
    private external fun mockTests(applicationContext: Context): String
    private external fun realWorldTests(applicationContext: Context): String
    private external fun verifyMockRootUsage(applicationContext: Context): String

    companion object {
        @BeforeClass
        @JvmStatic
        fun init() {
            System.loadLibrary("rustls_platform_verifier")
        }
    }

    @Test
    fun runMockTestSuite() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val result = mockTests(context)
        assertEquals(FAILURE_MSG, SUCCESS_MARKER, result)
    }

    @Test
    fun runRealWorldTestSuite() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val result = realWorldTests(context)
        assertEquals(FAILURE_MSG, SUCCESS_MARKER, result)
    }

    @Test
    fun runVerifyMockRootUsage() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val result = verifyMockRootUsage(context)
        assertEquals(FAILURE_MSG, SUCCESS_MARKER, result)
    }

    // Note:
    //
    // - Full negative path (`CertificateVerifier`'s flow for unknown roots,
    // end-entity-only revocation check) already exercised via `runMockTestSuite`.
    //
    // - Full positive path (`CertificateVerifier`'s flow for known roots,
    // full-chain revocation check) already exercised via `runRealWorldTestSuite`.
    @Test
    fun runTestIsPublicRoot() {
        val rootCAs = CertificateVerifier.getSystemRootCAs()

        // Positive - can ID known roots
        assertTrue(rootCAs.isNotEmpty())
        for (ca in rootCAs) {
            assertTrue(CertificateVerifier.isKnownRoot(ca))
        }
    }
}
