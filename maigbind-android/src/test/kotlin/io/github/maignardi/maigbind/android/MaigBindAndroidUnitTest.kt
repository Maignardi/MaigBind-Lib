package io.github.maignardi.maigbind.android

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.StrongBoxUnavailableException
import androidx.fragment.app.FragmentActivity
import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.MaigBindError
import io.github.maignardi.maigbind.core.MaigBindResult
import io.github.maignardi.maigbind.core.PromptText
import io.github.maignardi.maigbind.core.SecurityBacking
import io.github.maignardi.maigbind.core.Sha256
import io.github.maignardi.maigbind.core.TransactionPayload
import io.github.maignardi.maigbind.core.canonical
import io.github.maignardi.maigbind.core.canonicalFields
import io.github.maignardi.maigbind.core.computeKeyId
import io.github.maignardi.maigbind.core.toHexString
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
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
                    .apply { initialize(ECGenParameterSpec("secp256r1")) }
                    .generateKeyPair()
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

    private class InMemorySlotStore(
        private val salt: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) },
    ) : KeyAliasSlotStore {
        private val active = mutableMapOf<String, String>()
        private val pending = mutableMapOf<String, String>()

        override fun getOrCreateInstallSalt(): ByteArray = salt

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

        override fun promotePendingToActive(accountHash: String): Pair<String?, String?> {
            val p = pending.remove(accountHash) ?: return null to null
            val prev = active[accountHash]
            active[accountHash] = p
            return p to prev
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

    private suspend fun enrollAndActivate(
        sdk: MaigBind,
        accountId: String,
        challengeByte: Byte = 1,
    ): String {
        val enrollRes =
            (
                sdk.enroll(
                    accountId,
                    Base64Url.encode(
                        ByteArray(32) {
                            challengeByte
                        },
                    ),
                ) as MaigBindResult.Success
            ).value
        sdk.activatePendingEnrollment(accountId)
        return enrollRes.keyId
    }

    @Test
    fun keystoreAliasUsesPerInstallSaltedHashToProtectLowEntropyCpfIds() =
        runTest {
            val cpf = "12345678900"
            val ks1 = FakeKeyStoreGateway()
            val slots1 = InMemorySlotStore()
            val sdk1 = MaigBind(MaigBindConfig(), ks1, FakeBiometricLauncher(), slots1)
            sdk1.enroll(cpf, Base64Url.encode(ByteArray(32) { 1 }))
            val alias1 = ks1.keys.keys.single()

            val ks2 = FakeKeyStoreGateway()
            val slots2 = InMemorySlotStore()
            val sdk2 = MaigBind(MaigBindConfig(), ks2, FakeBiometricLauncher(), slots2)
            sdk2.enroll(cpf, Base64Url.encode(ByteArray(32) { 1 }))
            val alias2 = ks2.keys.keys.single()

            val unsaltedHash = Sha256.digest(cpf.encodeToByteArray()).toHexString().take(24)
            assertFalse(alias1.contains(cpf))
            assertFalse(alias1.contains(unsaltedHash))
            assertNotEquals(alias1, alias2) // different random install salts produce distinct aliases
        }

    @Test
    fun initialAndReEnrollmentStayPendingUntilActivatedAndAbortNeverDeletesActiveKey() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val slots = InMemorySlotStore()
            val sdk = MaigBind(MaigBindConfig(), ks, FakeBiometricLauncher(), slots)
            val activity = createActivity()

            // Initial enrollment starts as pending; not active until server confirms ACTIVE
            val first = (sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 1 })) as MaigBindResult.Success).value
            assertFalse(sdk.hasEnrolledKey("user-1"))
            assertNull(sdk.getEnrolledKeyId("user-1"))
            assertEquals(first.keyId, sdk.getPendingKeyId("user-1"))

            sdk.activatePendingEnrollment("user-1")
            assertTrue(sdk.hasEnrolledKey("user-1"))
            assertEquals(first.keyId, sdk.getEnrolledKeyId("user-1"))
            assertNull(sdk.getPendingKeyId("user-1"))

            // Start re-enrollment while active key exists -> staged in pending slot
            val second = (sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 2 })) as MaigBindResult.Success).value
            assertEquals(first.keyId, sdk.getEnrolledKeyId("user-1"))
            assertEquals(second.keyId, sdk.getPendingKeyId("user-1"))
            assertEquals(2, ks.keys.size)

            // Guard: even if slots had pending == active (simulated corruption), abort MUST NOT delete active
            val hash = MaigBind.accountHash("user-1", slots.getOrCreateInstallSalt())
            val activeAlias = slots.getActiveAlias(hash)!!
            slots.setPendingAlias(hash, activeAlias)
            sdk.abortPendingEnrollment("user-1")
            assertTrue(sdk.hasEnrolledKey("user-1"))
            assertNotNull(ks.getPrivateKeyOrNull(activeAlias))

            // Normal abort cleans up pending and keeps active key signing
            val third = (sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 3 })) as MaigBindResult.Success).value
            sdk.abortPendingEnrollment("user-1")
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
            assertNotEquals(first.keyId, third.keyId)
        }

    @Test
    fun reconcileActiveKeyRecoversAfterCrashBetweenServerActivationAndClientPromotion() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val slots = InMemorySlotStore()
            val sdk = MaigBind(MaigBindConfig(), ks, FakeBiometricLauncher(), slots)

            val k1 = enrollAndActivate(sdk, "user-1", 1)
            val k2 = (sdk.enroll("user-1", Base64Url.encode(ByteArray(32) { 2 })) as MaigBindResult.Success).value.keyId

            // Server activated k2, but client crashed before activatePendingEnrollment()
            assertEquals(k1, sdk.getEnrolledKeyId("user-1"))
            assertEquals(k2, sdk.getPendingKeyId("user-1"))

            val rec = (sdk.reconcileActiveKey("user-1", k2) as MaigBindResult.Success).value
            assertEquals(ReconciliationOutcome.PROMOTED_PENDING, rec)
            assertEquals(k2, sdk.getEnrolledKeyId("user-1"))
            assertNull(sdk.getPendingKeyId("user-1"))
            assertEquals(1, ks.keys.size)

            // Subsequent reconcile is UP_TO_DATE
            assertEquals(
                ReconciliationOutcome.UP_TO_DATE,
                (sdk.reconcileActiveKey("user-1", k2) as MaigBindResult.Success).value,
            )

            // Unknown server keyId requires re-enrollment
            assertEquals(
                ReconciliationOutcome.NEEDS_RE_ENROLLMENT,
                (sdk.reconcileActiveKey("user-1", "different-device-key") as MaigBindResult.Success).value,
            )

            // Server null clears stale local slots
            assertEquals(
                ReconciliationOutcome.NOT_ENROLLED,
                (sdk.reconcileActiveKey("user-1", null) as MaigBindResult.Success).value,
            )
            assertFalse(sdk.hasEnrolledKey("user-1"))
        }

    @Test
    fun rejectsFridaHookReturningNullCryptoObjectOrSwappedSignature() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val bioNull = FakeBiometricLauncher { BiometricPromptOutcome.Succeeded(returnedSignature = null) }
            val sdkNull = MaigBind(MaigBindConfig(), ks, bioNull, InMemorySlotStore())
            val keyId1 = enrollAndActivate(sdkNull, "user-1", 1)
            val tx =
                TransactionPayload(
                    keyId = keyId1,
                    operationType = "PIX_TRANSFER",
                    nonce = "n1",
                    issuedAt = 1000L,
                    expiresAt = 2000L,
                )

            val resNull = sdkNull.sign(createActivity(), "user-1", tx, prompt)
            assertTrue((resNull as MaigBindResult.Failure).error is MaigBindError.CryptoObjectTampered)

            val rogueSig = Signature.getInstance("SHA256withECDSA")
            val bioSwap = FakeBiometricLauncher { BiometricPromptOutcome.Succeeded(returnedSignature = rogueSig) }
            val sdkSwap = MaigBind(MaigBindConfig(), ks, bioSwap, InMemorySlotStore())
            val keyId2 = enrollAndActivate(sdkSwap, "user-2", 2)
            val resSwap = sdkSwap.sign(createActivity(), "user-2", tx.copy(keyId = keyId2), prompt)
            assertTrue((resSwap as MaigBindResult.Failure).error is MaigBindError.CryptoObjectTampered)
        }

    @Test
    fun signsWithStrongBiometricAndProducesVerifiableEcdsaSignature() =
        runTest {
            val ks = FakeKeyStoreGateway()
            val sdk = MaigBind(MaigBindConfig(), ks, FakeBiometricLauncher(), InMemorySlotStore())
            val keyId = enrollAndActivate(sdk, "user-1", 9)

            val tx =
                TransactionPayload(
                    keyId = keyId,
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
            assertEquals(keyId, computeKeyId(pubKey.encoded))
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
                TransactionPayload(keyId = "missing", operationType = "TX", nonce = "n", issuedAt = 1L, expiresAt = 2L)
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

            val keyId = enrollAndActivate(sdk, "user-1", 2)
            val tx = missingTx.copy(keyId = keyId)

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
