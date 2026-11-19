package io.github.maignardi.maigbind.android

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.MaigBindError
import io.github.maignardi.maigbind.core.MaigBindResult
import io.github.maignardi.maigbind.core.PromptText
import io.github.maignardi.maigbind.core.SecurityBacking
import io.github.maignardi.maigbind.core.TransactionPayload
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

/**
 * Android instrumented tests exercising real `AndroidKeyStore`, StrongBox-to-TEE fallback,
 * `KeyInfo` biometric invalidation flags, prompt cancellation, and key lifecycle on an Android
 * device/emulator.
 */
@RunWith(AndroidJUnit4::class)
class MaigBindInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun hardwareKeyGenerationReportsStrongBoxOrFallsBackToTeeAndEnforcesBiometricInvalidation() =
        runTest {
            val sdk = MaigBind(context)
            sdk.unenroll("instrumented-test")
            assumeTrue(
                "Device must have BIOMETRIC_STRONG enrolled to test biometric-bound key generation",
                sdk.getBiometricCapability() == BiometricCapability.READY_STRONG,
            )

            val result = sdk.enroll("instrumented-test", Base64Url.encode(ByteArray(32) { 0x42 }))
            assertTrue("Expected enrollment success, got $result", result is MaigBindResult.Success)
            val req = (result as MaigBindResult.Success).value
            assertTrue(req.securityBacking == SecurityBacking.STRONGBOX || req.securityBacking == SecurityBacking.TEE)
            assertTrue(req.attestationChainBase64Url.isNotEmpty())
            assertFalse(sdk.hasEnrolledKey("instrumented-test"))
            assertEquals(req.keyId, sdk.getPendingKeyId("instrumented-test"))

            sdk.activatePendingEnrollment("instrumented-test")
            assertTrue(sdk.hasEnrolledKey("instrumented-test"))

            // Verify KeyInfo enforces biometric authentication, per-use validity, and invalidation on new enrollment
            val slotStore = SharedPrefsKeyAliasSlotStore(context)
            val alias =
                slotStore.getActiveAlias(
                    MaigBind.accountHash("instrumented-test", slotStore.getOrCreateInstallSalt()),
                )!!
            val privateKey = PlatformAndroidKeyStoreGateway().getPrivateKeyOrNull(alias)!!
            val keyInfo =
                KeyFactory
                    .getInstance(privateKey.algorithm, "AndroidKeyStore")
                    .getKeySpec(privateKey, KeyInfo::class.java)
            assertTrue(keyInfo.isUserAuthenticationRequired)
            assertTrue(keyInfo.isInvalidatedByBiometricEnrollment)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                assertEquals(0, keyInfo.userAuthenticationValidityDurationSeconds)
                assertTrue((keyInfo.userAuthenticationType and KeyProperties.AUTH_BIOMETRIC_STRONG) != 0)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                assertTrue(
                    keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
                        keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                )
            }

            sdk.unenroll("instrumented-test")
            assertFalse(sdk.hasEnrolledKey("instrumented-test"))
        }

    @Test
    fun unenrolledBiometricsReturnsBiometryNotEnrolledWithoutCrashing() =
        runTest {
            val sdk = MaigBind(context)
            val cap = sdk.getBiometricCapability()
            if (cap == BiometricCapability.NONE_ENROLLED) {
                val res = sdk.enroll("no-bio-user", Base64Url.encode(ByteArray(32) { 0x11 }))
                assertTrue(res is MaigBindResult.Failure)
                assertEquals(MaigBindError.BiometryNotEnrolled::class, (res as MaigBindResult.Failure).error::class)
            }
        }

    @Test
    fun requireStrongBoxReturnsHardwareUnavailableWhenMissing() =
        runTest {
            val hasStrongBox =
                runCatching {
                    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                    val spec =
                        KeyGenParameterSpec
                            .Builder("maigbind:sb-probe", KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                            .setIsStrongBoxBacked(true)
                            .build()
                    kpg.initialize(spec)
                    kpg.generateKeyPair()
                    KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry("maigbind:sb-probe")
                    true
                }.getOrElse { ex ->
                    if (ex is StrongBoxUnavailableException) false else true
                }

            if (!hasStrongBox) {
                val sdk = MaigBind(context, MaigBindConfig(requireStrongBox = true))
                assumeTrue(sdk.getBiometricCapability() == BiometricCapability.READY_STRONG)
                val res = sdk.enroll("sb-strict", Base64Url.encode(ByteArray(32) { 0x55 }))
                assertTrue(res is MaigBindResult.Failure)
                assertTrue((res as MaigBindResult.Failure).error is MaigBindError.HardwareUnavailable)
            }
        }

    @Test
    fun cancellingBiometricPromptJobCancelsCleanlyWithoutCrashing() =
        runTest {
            val sdk = MaigBind(context)
            assumeTrue(sdk.getBiometricCapability() == BiometricCapability.READY_STRONG)

            val enrollRes = sdk.enroll("cancel-test", Base64Url.encode(ByteArray(32) { 0x77 }))
            assumeTrue("Enrollment succeeded", enrollRes is MaigBindResult.Success)
            val keyId = (enrollRes as MaigBindResult.Success).value.keyId

            ActivityScenario.launch(FragmentActivity::class.java).use { scenario ->
                scenario.onActivity { activity ->
                    val job =
                        launch {
                            val payload =
                                TransactionPayload(
                                    keyId = keyId,
                                    operationType = "PIX_TRANSFER",
                                    nonce = "cancel-nonce",
                                    issuedAt = System.currentTimeMillis(),
                                    expiresAt = System.currentTimeMillis() + 60_000L,
                                )
                            sdk.sign(
                                activity = activity,
                                accountId = "cancel-test",
                                payload = payload,
                                promptText = PromptText("Cancel Test", "Tap cancel"),
                            )
                        }
                    job.cancel()
                    assertTrue(job.isCancelled)
                }
            }
            sdk.unenroll("cancel-test")
        }
}
