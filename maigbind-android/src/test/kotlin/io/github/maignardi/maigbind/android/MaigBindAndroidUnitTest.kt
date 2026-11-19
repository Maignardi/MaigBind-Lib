package io.github.maignardi.maigbind.android

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.github.maignardi.maigbind.core.AuthPolicyUsed
import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.MaigBindError
import io.github.maignardi.maigbind.core.MaigBindResult
import io.github.maignardi.maigbind.core.PromptText
import io.github.maignardi.maigbind.core.SecurityBacking
import io.github.maignardi.maigbind.core.TransactionPayload
import io.github.maignardi.maigbind.core.canonical
import io.github.maignardi.maigbind.core.canonicalFields
import io.github.maignardi.maigbind.core.computeKeyId
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

@RunWith(RobolectricTestRunner::class)
class MaigBindAndroidUnitTest {
    private class FakeKeyStoreGateway : AndroidKeyStoreGateway {
        val keys = mutableMapOf<String, Pair<KeyPair, SecurityBacking>>()
        var failNextInitWithInvalidated = false
        var failStrongBoxWithUnavailable = false

        override fun generateHardwareKey(
            alias: String,
            attestationChallenge: ByteArray,
            config: MaigBindConfig,
        ): GeneratedKeyMaterial {
            if (config.requireStrongBox && failStrongBoxWithUnavailable) {
                throw StrongBoxUnavailableException("No StrongBox HSM")
            }
            val kp =
                KeyPairGenerator
                    .getInstance("EC")
                    .apply {
                        initialize(ECGenParameterSpec("secp256r1"))
                    }.generateKeyPair()
            val backing =
                if (config.preferStrongBox && !failStrongBoxWithUnavailable) {
                    SecurityBacking.STRONGBOX
                } else {
                    SecurityBacking.TEE
                }
            keys[alias] = kp to backing
            return GeneratedKeyMaterial(
                publicKeySpkiDer = kp.public.encoded,
                attestationChainDer = listOf(kp.public.encoded), // Mock chain for unit test
                securityBacking = backing,
            )
        }

        override fun getPrivateKeyOrNull(alias: String): PrivateKey? {
            if (failNextInitWithInvalidated) {
                failNextInitWithInvalidated = false
                throw KeyPermanentlyInvalidatedException("Biometrics changed")
            }
            return keys[alias]?.first?.private
        }

        override fun getPublicKeySpkiOrNull(alias: String): ByteArray? = keys[alias]?.first?.public?.encoded

        override fun getKeySecurityBacking(
            alias: String,
            privateKey: PrivateKey,
        ): SecurityBacking = keys[alias]?.second ?: SecurityBacking.UNKNOWN

        override fun deleteKey(alias: String) {
            keys.remove(alias)
        }
    }

    private class FakeBiometricLauncher(
        var capability: BiometricCapability = BiometricCapability.READY_STRONG,
        var outcomeProvider: (Signature) -> BiometricPromptOutcome = { BiometricPromptOutcome.Succeeded(it) },
    ) : BiometricPromptLauncher {
        var lastAuthenticators: Int = -1

        override fun checkCapability(allowWeak: Boolean): BiometricCapability = capability

        override suspend fun authenticate(
            activity: FragmentActivity,
            title: String,
            subtitle: String?,
            description: String?,
            negativeButtonText: String,
            authenticators: Int,
            signature: Signature,
        ): BiometricPromptOutcome {
            lastAuthenticators = authenticators
            return outcomeProvider(signature)
        }
    }

    private fun createActivity(): FragmentActivity =
        Robolectric.buildActivity(FragmentActivity::class.java).setup().get()

    private val prompt =
        PromptText(
            title = "Approve PIX Transfer",
            subtitle = "R$ 1.500,00 to Alice",
            description = "Hardware biometric signature required",
        )

    @Test
    fun rejectsFridaHookReturningNullCryptoObject() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val bio =
                FakeBiometricLauncher {
                    // Simulates Universal Android Biometric Bypass returning AuthenticationResult(null)
                    BiometricPromptOutcome.Succeeded(returnedSignature = null)
                }
            val sdk = MaigBind(MaigBindConfig(), ks, bio)
            val enrollRes = sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 1 }))
            assertTrue(enrollRes is MaigBindResult.Success)
            val keyId = (enrollRes as MaigBindResult.Success).value.keyId

            val tx =
                TransactionPayload(
                    keyId = keyId,
                    operationType = "PIX_TRANSFER",
                    nonce = "nonce-1",
                    issuedAt = 1000L,
                    expiresAt = 2000L,
                    fields = canonicalFields("amountCents" to canonical(150_000L)),
                )
            val signRes = sdk.sign(createActivity(), "user-1", tx, prompt)
            assertTrue(signRes is MaigBindResult.Failure)
            assertTrue((signRes as MaigBindResult.Failure).error is MaigBindError.CryptoObjectTampered)
        }

    @Test
    fun rejectsFridaHookSwappingSignatureInstance() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val rogueSignature = Signature.getInstance("SHA256withECDSA")
            val bio =
                FakeBiometricLauncher {
                    // Simulates Frida replacing result.cryptoObject with a different Signature object
                    BiometricPromptOutcome.Succeeded(returnedSignature = rogueSignature)
                }
            val sdk = MaigBind(MaigBindConfig(), ks, bio)
            val enrollRes = sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 1 })) as MaigBindResult.Success

            val tx =
                TransactionPayload(
                    keyId = enrollRes.value.keyId,
                    operationType = "PIX_TRANSFER",
                    nonce = "nonce-2",
                    issuedAt = 1000L,
                    expiresAt = 2000L,
                )
            val signRes = sdk.sign(createActivity(), "user-1", tx, prompt)
            assertTrue(signRes is MaigBindResult.Failure)
            assertTrue((signRes as MaigBindResult.Failure).error is MaigBindError.CryptoObjectTampered)
        }

    @Test
    fun signsWithStrongBiometricAndProducesVerifiableEcdsaSignature() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val bio = FakeBiometricLauncher()
            val sdk = MaigBind(MaigBindConfig(), ks, bio)

            val enroll = (sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 9 })) as MaigBindResult.Success).value
            assertEquals(SecurityBacking.STRONGBOX, enroll.securityBacking)

            val tx =
                TransactionPayload(
                    keyId = enroll.keyId,
                    operationType = "PIX_TRANSFER",
                    nonce = "nonce-3",
                    issuedAt = 1000L,
                    expiresAt = 2000L,
                    fields = canonicalFields("amountCents" to canonical(50_000L)),
                )
            val signed = (sdk.sign(createActivity(), "user-1", tx, prompt) as MaigBindResult.Success).value
            assertEquals(BiometricManager.Authenticators.BIOMETRIC_STRONG, bio.lastAuthenticators)
            assertEquals(AuthPolicyUsed.BIOMETRIC_STRONG, signed.authMetadata.authPolicyUsed)

            val pubKey = ks.keys["maigbind:user-1"]!!.first.public
            assertEquals(enroll.keyId, computeKeyId(pubKey.encoded))
            val verifier =
                Signature.getInstance("SHA256withECDSA").apply {
                    initVerify(pubKey)
                    update(tx.signingInput())
                }
            assertTrue(verifier.verify(Base64Url.decode(signed.signatureBase64Url)))
        }

    @Test
    fun mapsNotEnrolledCancelledLockoutAndBiometricInvalidation() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val bio = FakeBiometricLauncher()
            val sdk = MaigBind(MaigBindConfig(), ks, bio)

            val missingTx =
                TransactionPayload(
                    keyId = "missing",
                    operationType = "TX",
                    nonce = "n",
                    issuedAt = 1L,
                    expiresAt = 2L,
                )
            val notEnrolled = sdk.sign(createActivity(), "unknown-user", missingTx, prompt)
            assertTrue((notEnrolled as MaigBindResult.Failure).error is MaigBindError.NotEnrolled)

            val enroll = (sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 2 })) as MaigBindResult.Success).value
            val tx = missingTx.copy(keyId = enroll.keyId)

            bio.outcomeProvider = { BiometricPromptOutcome.Error(BiometricPrompt.ERROR_USER_CANCELED, "Cancelled") }
            val cancelled = sdk.sign(createActivity(), "user-1", tx, prompt)
            assertTrue((cancelled as MaigBindResult.Failure).error is MaigBindError.Cancelled)

            bio.outcomeProvider = { BiometricPromptOutcome.Error(BiometricPrompt.ERROR_LOCKOUT_PERMANENT, "Locked") }
            val lockout = sdk.sign(createActivity(), "user-1", tx, prompt)
            val lockoutErr = (lockout as MaigBindResult.Failure).error as MaigBindError.Lockout
            assertTrue(lockoutErr.isPermanent)

            // Simulate KeyPermanentlyInvalidatedException when Signature.initSign is invoked
            val invalidatedSdk =
                MaigBind(
                    config = MaigBindConfig(),
                    keyStoreGateway = ks,
                    biometricLauncher = FakeBiometricLauncher(),
                    signatureFactory = {
                        throw KeyPermanentlyInvalidatedException("New fingerprint added")
                    },
                )
            val needsReEnroll = invalidatedSdk.sign(createActivity(), "user-1", tx, prompt)
            assertTrue((needsReEnroll as MaigBindResult.Failure).error is MaigBindError.NeedsReEnrollment)
            assertFalse(invalidatedSdk.hasEnrolledKey("user-1"))
        }

    @Test
    fun blocksWeakBiometricByDefaultAndFlagsExplicitOptIn() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val bio = FakeBiometricLauncher(capability = BiometricCapability.READY_WEAK_ONLY)

            val strictSdk = MaigBind(MaigBindConfig(allowWeakBiometricFallback = false), ks, bio)
            val blocked = strictSdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 3 }))
            assertTrue((blocked as MaigBindResult.Failure).error is MaigBindError.BiometryUnavailable)

            val optInSdk = MaigBind(MaigBindConfig(allowWeakBiometricFallback = true), ks, bio)
            val allowed = optInSdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 3 }))
            assertTrue(allowed is MaigBindResult.Success)
            assertEquals(AuthPolicyUsed.BIOMETRIC_WEAK_OPT_IN, (allowed as MaigBindResult.Success).value.authPolicyUsed)
        }
}
