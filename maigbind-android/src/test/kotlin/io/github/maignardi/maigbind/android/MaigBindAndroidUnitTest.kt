package io.github.maignardi.maigbind.android

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.StrongBoxUnavailableException
import androidx.fragment.app.FragmentActivity
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
import org.junit.Assert.assertNotNull
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
                attestationChainDer = listOf(kp.public.encoded),
                securityBacking = backing,
            )
        }

        override fun getPrivateKeyOrNull(alias: String): PrivateKey? = keys[alias]?.first?.private

        override fun getPublicKeySpkiOrNull(alias: String): ByteArray? = keys[alias]?.first?.public?.encoded

        override fun getKeySecurityBacking(
            alias: String,
            privateKey: PrivateKey,
        ): SecurityBacking = keys[alias]?.second ?: SecurityBacking.UNKNOWN

        override fun deleteKey(alias: String) {
            keys.remove(alias)
        }
    }

    private class InMemorySlotStore : KeyAliasSlotStore {
        private val active = mutableMapOf<String, String>()
        private val pending = mutableMapOf<String, String>()

        override fun getActiveAlias(accountHash: String): String? = active[accountHash]

        override fun setActiveAlias(
            accountHash: String,
            alias: String?,
        ) {
            if (alias == null) active.remove(accountHash) else active[accountHash] = alias
        }

        override fun getPendingAlias(accountHash: String): String? = pending[accountHash]

        override fun setPendingAlias(
            accountHash: String,
            alias: String?,
        ) {
            if (alias == null) pending.remove(accountHash) else pending[accountHash] = alias
        }
    }

    private class FakeBiometricLauncher(
        var capability: BiometricCapability = BiometricCapability.READY_STRONG,
        var outcomeProvider: (Signature) -> BiometricPromptOutcome = { BiometricPromptOutcome.Succeeded(it) },
    ) : BiometricPromptLauncher {
        override fun checkCapability(): BiometricCapability = capability

        override suspend fun authenticate(
            activity: FragmentActivity,
            title: String,
            subtitle: String?,
            description: String?,
            negativeButtonText: String,
            signature: Signature,
        ): BiometricPromptOutcome = outcomeProvider(signature)
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
    fun keystoreAliasHashesAccountIdAndNeverStoresPii() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val sdk = MaigBind(MaigBindConfig(), ks, FakeBiometricLauncher(), InMemorySlotStore())
            val piiAccount = "maria.silva+12345678900@banco.com.br"
            val enrollRes = sdk.enroll(piiAccount, Base64Url.encode(ByteArray(32) { 1 }))
            assertTrue(enrollRes is MaigBindResult.Success)
            val alias = ks.keys.keys.single()
            assertFalse(alias.contains("maria"))
            assertFalse(alias.contains("12345678900"))
            assertTrue(alias.startsWith("maigbind:${MaigBind.accountHash(piiAccount)}:"))
        }

    @Test
    fun reEnrollmentStagesPendingKeyWithoutDestroyingActiveKeyUntilPromoted() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val slots = InMemorySlotStore()
            val bio = FakeBiometricLauncher()
            val sdk = MaigBind(MaigBindConfig(), ks, bio, slots)
            val activity = createActivity()

            val first = (sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 1 })) as MaigBindResult.Success).value
            assertEquals(first.keyId, sdk.getEnrolledKeyId("user-1"))

            // Start re-enrollment while active key exists -> staged in pending slot
            val second = (sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 2 })) as MaigBindResult.Success).value
            assertEquals(first.keyId, sdk.getEnrolledKeyId("user-1"))
            assertEquals(second.keyId, sdk.getPendingKeyId("user-1"))
            assertEquals(2, ks.keys.size)

            // Active key still signs normally if pending re-enrollment is aborted
            sdk.abortPendingEnrollment("user-1")
            assertEquals(1, ks.keys.size)
            assertEquals(first.keyId, sdk.getEnrolledKeyId("user-1"))
            val txOld =
                TransactionPayload(
                    keyId = first.keyId,
                    operationType = "PIX_TRANSFER",
                    nonce = "n1",
                    issuedAt = 100L,
                    expiresAt = 200L,
                )
            assertTrue(sdk.sign(activity, "user-1", txOld, prompt) is MaigBindResult.Success)

            // Now re-enroll, confirm PoP on pending key, and promote
            val third = (sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 3 })) as MaigBindResult.Success).value
            val pop =
                sdk.confirmEnrollmentPop(
                    activity = activity,
                    bindingId = "bind-3",
                    accountId = "user-1",
                    popChallengeBase64Url = Base64Url.encode(ByteArray(32) { 4 }),
                    issuedAt = 100L,
                    expiresAt = 200L,
                    promptText = prompt,
                )
            assertTrue(pop is MaigBindResult.Success)
            assertEquals(third.keyId, (pop as MaigBindResult.Success).value.popPayload.keyId)

            sdk.activatePendingEnrollment("user-1")
            assertEquals(third.keyId, sdk.getEnrolledKeyId("user-1"))
            assertEquals(null, sdk.getPendingKeyId("user-1"))
            assertEquals(1, ks.keys.size)
        }

    @Test
    fun rejectsFridaHookReturningNullCryptoObjectOrSwappedSignature() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val bioNull = FakeBiometricLauncher { BiometricPromptOutcome.Succeeded(returnedSignature = null) }
            val sdkNull = MaigBind(MaigBindConfig(), ks, bioNull, InMemorySlotStore())
            val enrollRes =
                (
                    sdkNull.enroll(
                        "user-1",
                        Base64Url.encode(ByteArray(32) { 1 }),
                    ) as MaigBindResult.Success
                ).value
            val tx =
                TransactionPayload(
                    keyId = enrollRes.keyId,
                    operationType = "PIX_TRANSFER",
                    nonce = "n1",
                    issuedAt = 1000L,
                    expiresAt = 2000L,
                )

            val resNull = sdkNull.sign(createActivity(), "user-1", tx, prompt)
            assertTrue((resNull as MaigBindResult.Failure).error is MaigBindError.CryptoObjectTampered)

            val rogueSig = Signature.getInstance("SHA256withECDSA")
            val bioSwap = FakeBiometricLauncher { BiometricPromptOutcome.Succeeded(returnedSignature = rogueSig) }
            val slots = InMemorySlotStore()
            val sdkSwap = MaigBind(MaigBindConfig(), ks, bioSwap, slots)
            val e2 = (sdkSwap.enroll("user-2", Base64Url.encode(ByteArray(32) { 2 })) as MaigBindResult.Success).value
            val resSwap = sdkSwap.sign(createActivity(), "user-2", tx.copy(keyId = e2.keyId), prompt)
            assertTrue((resSwap as MaigBindResult.Failure).error is MaigBindError.CryptoObjectTampered)
        }

    @Test
    fun signsWithStrongBiometricAndProducesVerifiableEcdsaSignature() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val sdk = MaigBind(MaigBindConfig(), ks, FakeBiometricLauncher(), InMemorySlotStore())
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
            val pubKey =
                ks.keys.values
                    .single()
                    .first.public
            assertNotNull(pubKey)
            assertEquals(enroll.keyId, computeKeyId(pubKey.encoded))
            val verifier =
                Signature.getInstance("SHA256withECDSA").apply {
                    initVerify(pubKey)
                    update(tx.signingInput())
                }
            assertTrue(verifier.verify(Base64Url.decode(signed.signatureBase64Url)))
        }

    @Test
    fun mapsNotEnrolledCancelledLockoutBiometryUnavailableAndInvalidation() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val bio = FakeBiometricLauncher()
            val slots = InMemorySlotStore()
            val sdk = MaigBind(MaigBindConfig(), ks, bio, slots)

            val missingTx =
                TransactionPayload(
                    keyId = "missing",
                    operationType = "TX",
                    nonce = "n",
                    issuedAt = 1L,
                    expiresAt = 2L,
                )
            assertTrue(
                (
                    sdk.sign(
                        createActivity(),
                        "unknown",
                        missingTx,
                        prompt,
                    ) as MaigBindResult.Failure
                ).error is MaigBindError.NotEnrolled,
            )

            val enroll = (sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 2 })) as MaigBindResult.Success).value
            val tx = missingTx.copy(keyId = enroll.keyId)

            bio.outcomeProvider =
                { BiometricPromptOutcome.Error(androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED, "Cancelled") }
            assertTrue(
                (
                    sdk.sign(
                        createActivity(),
                        "user-1",
                        tx,
                        prompt,
                    ) as MaigBindResult.Failure
                ).error is MaigBindError.Cancelled,
            )

            bio.outcomeProvider =
                { BiometricPromptOutcome.Error(androidx.biometric.BiometricPrompt.ERROR_LOCKOUT_PERMANENT, "Locked") }
            val lockoutErr =
                (
                    sdk.sign(
                        createActivity(),
                        "user-1",
                        tx,
                        prompt,
                    ) as MaigBindResult.Failure
                ).error as MaigBindError.Lockout
            assertTrue(lockoutErr.isPermanent)

            val invalidatedSdk =
                MaigBind(
                    config = MaigBindConfig(),
                    keyStoreGateway = ks,
                    biometricLauncher = FakeBiometricLauncher(),
                    aliasSlotStore = slots,
                    signatureFactory = { throw KeyPermanentlyInvalidatedException("New fingerprint added") },
                )
            val needsReEnroll = invalidatedSdk.sign(createActivity(), "user-1", tx, prompt)
            assertTrue((needsReEnroll as MaigBindResult.Failure).error is MaigBindError.NeedsReEnrollment)
            assertFalse(invalidatedSdk.hasEnrolledKey("user-1"))

            bio.capability = BiometricCapability.NONE_ENROLLED
            val noBio = sdk.enroll("user-no-bio", Base64Url.encode(ByteArray(32) { 4 }))
            assertTrue((noBio as MaigBindResult.Failure).error is MaigBindError.BiometryNotEnrolled)
        }
}
