package io.github.maignardi.maigbind.android

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.EnrollmentConfirmRequest
import io.github.maignardi.maigbind.core.EnrollmentPoPPayload
import io.github.maignardi.maigbind.core.EnrollmentRequest
import io.github.maignardi.maigbind.core.MaigBindError
import io.github.maignardi.maigbind.core.MaigBindResult
import io.github.maignardi.maigbind.core.PromptText
import io.github.maignardi.maigbind.core.Sha256
import io.github.maignardi.maigbind.core.SignedPayload
import io.github.maignardi.maigbind.core.TransactionPayload
import io.github.maignardi.maigbind.core.computeKeyId
import io.github.maignardi.maigbind.core.toHexString
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.PrivateKey
import java.security.Signature
import java.util.UUID

/**
 * Android client SDK for MaigBind.
 *
 * Generates non-exportable EC P-256 keys in StrongBox/TEE under per-install salted SHA-256
 * aliases (protecting even low-entropy identifiers like national IDs/CPFs from brute-force
 * reversal), bound to `BIOMETRIC_STRONG` per-use authentication (`CryptoObject`), and signs
 * canonical CBOR payloads for server-side verification.
 *
 * Key lifecycle:
 * - Every [enroll] call (including initial enrollment) stages the newly generated key in a
 *   `pending` slot.
 * - [confirmEnrollmentPop] signs the Proof-of-Possession challenge using that pending key.
 * - Once the server confirms `ACTIVE`, call [activatePendingEnrollment] to atomically promote the
 *   pending slot to `active` and delete any superseded key (or [abortPendingEnrollment] on failure).
 * - If the app crashes between server `ACTIVE` and [activatePendingEnrollment], call
 *   [reconcileActiveKey] on startup with the `keyId` reported by your backend.
 */
public class MaigBind internal constructor(
    private val config: MaigBindConfig,
    private val keyStoreGateway: AndroidKeyStoreGateway,
    private val biometricLauncher: BiometricPromptLauncher,
    private val aliasSlotStore: KeyAliasSlotStore,
    private val signatureFactory: () -> Signature = { Signature.getInstance("SHA256withECDSA") },
) {
    /**
     * Creates a [MaigBind] instance backed by `AndroidKeyStore` and `androidx.biometric.BiometricPrompt`.
     */
    public constructor(
        context: Context,
        config: MaigBindConfig = MaigBindConfig(),
    ) : this(
        config = config,
        keyStoreGateway = PlatformAndroidKeyStoreGateway(),
        biometricLauncher = PlatformBiometricPromptLauncher(context.applicationContext),
        aliasSlotStore = SharedPrefsKeyAliasSlotStore(context.applicationContext),
    )

    /** Checks whether Class 3 (`BIOMETRIC_STRONG`) authentication is available and enrolled. */
    public fun getBiometricCapability(): BiometricCapability = biometricLauncher.checkCapability()

    /** Returns `true` if an activated hardware key exists for [accountId]. */
    public suspend fun hasEnrolledKey(accountId: String): Boolean =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) return@withContext false
            val alias = resolveActiveAlias(accountId) ?: return@withContext false
            keyStoreGateway.getPrivateKeyOrNull(alias) != null
        }

    /** Returns the deterministic `keyId` (`base64url(SHA-256(spki))`) for [accountId]'s active key. */
    public suspend fun getEnrolledKeyId(accountId: String): String? =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) return@withContext null
            val alias = resolveActiveAlias(accountId) ?: return@withContext null
            keyStoreGateway.getPublicKeySpkiOrNull(alias)?.let(::computeKeyId)
        }

    /** Returns the `keyId` of a staged-but-unactivated pending key for [accountId], if any. */
    public suspend fun getPendingKeyId(accountId: String): String? =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) return@withContext null
            val alias = aliasSlotStore.getPendingAlias(saltedAccountHash(accountId)) ?: return@withContext null
            keyStoreGateway.getPublicKeySpkiOrNull(alias)?.let(::computeKeyId)
        }

    /**
     * Step 1 of enrollment: generates a non-exportable EC P-256 hardware key for [accountId]
     * bound to [serverChallengeBase64Url] and stages it in the `pending` slot.
     *
     * Any existing `active` key remains untouched until [activatePendingEnrollment] is invoked after
     * the server confirms `EnrollmentStatus.ACTIVE`.
     */
    public suspend fun enroll(
        accountId: String,
        serverChallengeBase64Url: String,
    ): MaigBindResult<EnrollmentRequest> =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) {
                return@withContext MaigBindResult.Failure(MaigBindError.InvalidInput("accountId must not be blank"))
            }
            val challengeBytes = runCatching { Base64Url.decode(serverChallengeBase64Url) }.getOrNull()
            if (challengeBytes == null || challengeBytes.isEmpty()) {
                return@withContext MaigBindResult.Failure(
                    MaigBindError.InvalidInput("serverChallengeBase64Url must be valid non-empty base64url"),
                )
            }
            val capabilityError = mapCapabilityToError(getBiometricCapability())
            if (capabilityError != null) {
                return@withContext MaigBindResult.Failure(capabilityError)
            }

            val hash = saltedAccountHash(accountId)
            val currentActive = aliasSlotStore.getActiveAlias(hash)
            val newAlias = freshAliasFor(hash)

            return@withContext try {
                val material =
                    keyStoreGateway.generateHardwareKey(
                        alias = newAlias,
                        attestationChallenge = challengeBytes,
                        config = config,
                    )
                // Purge any earlier unpromoted pending key before staging the new one.
                aliasSlotStore.getPendingAlias(hash)?.let { oldPending ->
                    if (oldPending != currentActive) {
                        runCatching { keyStoreGateway.deleteKey(oldPending) }
                    }
                }
                aliasSlotStore.setPendingAlias(hash, newAlias)

                MaigBindResult.Success(
                    EnrollmentRequest(
                        accountId = accountId,
                        keyId = computeKeyId(material.publicKeySpkiDer),
                        publicKeySpkiBase64Url = Base64Url.encode(material.publicKeySpkiDer),
                        attestationChainBase64Url = material.attestationChainDer.map { Base64Url.encode(it) },
                        challengeBase64Url = serverChallengeBase64Url,
                        securityBacking = material.securityBacking,
                    ),
                )
            } catch (ex: StrongBoxUnavailableException) {
                MaigBindResult.Failure(MaigBindError.HardwareUnavailable(ex.message ?: "StrongBox unavailable"))
            } catch (ex: Exception) {
                MaigBindResult.Failure(mapPlatformException(ex))
            }
        }

    /**
     * Step 2 of enrollment: signs the server-issued `popChallenge` with the staged `pending` key
     * using `BiometricPrompt` + `CryptoObject(Signature)`.
     */
    public suspend fun confirmEnrollmentPop(
        activity: FragmentActivity,
        bindingId: String,
        accountId: String,
        popChallengeBase64Url: String,
        issuedAt: Long,
        expiresAt: Long,
        promptText: PromptText,
    ): MaigBindResult<EnrollmentConfirmRequest> {
        if (bindingId.isBlank() || accountId.isBlank() || popChallengeBase64Url.isBlank()) {
            return MaigBindResult.Failure(
                MaigBindError.InvalidInput("bindingId, accountId, and popChallengeBase64Url must not be blank"),
            )
        }
        val hash = saltedAccountHash(accountId)
        val pendingAlias =
            aliasSlotStore.getPendingAlias(hash)
                ?: return MaigBindResult.Failure(MaigBindError.NotEnrolled(accountId))
        val spki =
            withContext(Dispatchers.IO) { keyStoreGateway.getPublicKeySpkiOrNull(pendingAlias) }
                ?: return MaigBindResult.Failure(MaigBindError.NotEnrolled(accountId))
        val keyId = computeKeyId(spki)

        val popPayload =
            EnrollmentPoPPayload(
                keyId = keyId,
                accountId = accountId,
                challenge = popChallengeBase64Url,
                issuedAt = issuedAt,
                expiresAt = expiresAt,
            )

        return when (
            val signed = signBytesWithAlias(activity, accountId, pendingAlias, popPayload.signingInput(), promptText)
        ) {
            is MaigBindResult.Failure -> signed
            is MaigBindResult.Success ->
                MaigBindResult.Success(
                    EnrollmentConfirmRequest(
                        bindingId = bindingId,
                        popPayload = popPayload,
                        signatureBase64Url = signed.value,
                    ),
                )
        }
    }

    /**
     * Atomically promotes the staged `pending` key to `active` for [accountId] after the server
     * confirms `EnrollmentStatus.ACTIVE`, and deletes any superseded active key from Keystore.
     */
    public suspend fun activatePendingEnrollment(accountId: String): MaigBindResult<Unit> =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) {
                return@withContext MaigBindResult.Failure(MaigBindError.InvalidInput("accountId must not be blank"))
            }
            val hash = saltedAccountHash(accountId)
            val (promoted, previousActive) = aliasSlotStore.promotePendingToActive(hash)
            if (promoted != null && previousActive != null && previousActive != promoted) {
                runCatching { keyStoreGateway.deleteKey(previousActive) }
            }
            MaigBindResult.Success(Unit)
        }

    /**
     * Deletes any unactivated pending enrollment key for [accountId], safely preserving any
     * existing active key (never deleting when `pending == active`).
     */
    public suspend fun abortPendingEnrollment(accountId: String): MaigBindResult<Unit> =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) {
                return@withContext MaigBindResult.Failure(MaigBindError.InvalidInput("accountId must not be blank"))
            }
            val hash = saltedAccountHash(accountId)
            val active = aliasSlotStore.getActiveAlias(hash)
            val pending = aliasSlotStore.getPendingAlias(hash)
            aliasSlotStore.setPendingAlias(hash, null)
            if (pending != null && pending != active) {
                runCatching { keyStoreGateway.deleteKey(pending) }
            }
            MaigBindResult.Success(Unit)
        }

    /**
     * Recovers from client-server key state desynchronization (e.g., when the server activated a
     * new binding and revoked the old one, but the app crashed before calling
     * [activatePendingEnrollment]).
     */
    public suspend fun reconcileActiveKey(
        accountId: String,
        serverActiveKeyId: String?,
    ): MaigBindResult<ReconciliationOutcome> =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) {
                return@withContext MaigBindResult.Failure(MaigBindError.InvalidInput("accountId must not be blank"))
            }
            val hash = saltedAccountHash(accountId)
            val activeKeyId = getEnrolledKeyId(accountId)
            val pendingKeyId = getPendingKeyId(accountId)

            if (serverActiveKeyId.isNullOrBlank()) {
                aliasSlotStore.getActiveAlias(hash)?.let { runCatching { keyStoreGateway.deleteKey(it) } }
                aliasSlotStore.getPendingAlias(hash)?.let { runCatching { keyStoreGateway.deleteKey(it) } }
                aliasSlotStore.setActiveAlias(hash, null)
                aliasSlotStore.setPendingAlias(hash, null)
                return@withContext MaigBindResult.Success(ReconciliationOutcome.NOT_ENROLLED)
            }

            if (activeKeyId == serverActiveKeyId) {
                return@withContext MaigBindResult.Success(ReconciliationOutcome.UP_TO_DATE)
            }

            if (pendingKeyId == serverActiveKeyId) {
                val (promoted, previousActive) = aliasSlotStore.promotePendingToActive(hash)
                if (promoted != null && previousActive != null && previousActive != promoted) {
                    runCatching { keyStoreGateway.deleteKey(previousActive) }
                }
                return@withContext MaigBindResult.Success(ReconciliationOutcome.PROMOTED_PENDING)
            }

            MaigBindResult.Success(ReconciliationOutcome.NEEDS_RE_ENROLLMENT)
        }

    /**
     * Prompts the user with `BiometricPrompt` (`BIOMETRIC_STRONG` + `CryptoObject(Signature)`)
     * displaying [promptText], and signs the canonical [payload] bytes using the active key.
     */
    public suspend fun sign(
        activity: FragmentActivity,
        accountId: String,
        payload: TransactionPayload,
        promptText: PromptText,
    ): MaigBindResult<SignedPayload> {
        if (accountId.isBlank()) {
            return MaigBindResult.Failure(MaigBindError.InvalidInput("accountId must not be blank"))
        }
        val activeAlias =
            resolveActiveAlias(accountId)
                ?: return MaigBindResult.Failure(MaigBindError.NotEnrolled(accountId))
        val enrolledKeyId =
            withContext(Dispatchers.IO) { keyStoreGateway.getPublicKeySpkiOrNull(activeAlias)?.let(::computeKeyId) }
                ?: return MaigBindResult.Failure(MaigBindError.NotEnrolled(accountId))
        if (payload.keyId != enrolledKeyId) {
            return MaigBindResult.Failure(
                MaigBindError.InvalidInput("TransactionPayload.keyId does not match enrolled key for '$accountId'"),
            )
        }

        return when (
            val signed = signBytesWithAlias(activity, accountId, activeAlias, payload.signingInput(), promptText)
        ) {
            is MaigBindResult.Failure -> signed
            is MaigBindResult.Success ->
                MaigBindResult.Success(
                    SignedPayload(
                        payload = payload,
                        signatureBase64Url = signed.value,
                    ),
                )
        }
    }

    /**
     * Deletes both active and any pending hardware keys for [accountId] from `AndroidKeyStore`.
     */
    public suspend fun unenroll(accountId: String): MaigBindResult<Unit> =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) {
                return@withContext MaigBindResult.Failure(MaigBindError.InvalidInput("accountId must not be blank"))
            }
            return@withContext try {
                val hash = saltedAccountHash(accountId)
                aliasSlotStore.getActiveAlias(hash)?.let { keyStoreGateway.deleteKey(it) }
                aliasSlotStore.getPendingAlias(hash)?.let { keyStoreGateway.deleteKey(it) }
                aliasSlotStore.setActiveAlias(hash, null)
                aliasSlotStore.setPendingAlias(hash, null)
                MaigBindResult.Success(Unit)
            } catch (ex: Exception) {
                MaigBindResult.Failure(mapPlatformException(ex))
            }
        }

    private suspend fun signBytesWithAlias(
        activity: FragmentActivity,
        accountId: String,
        alias: String,
        signingInput: ByteArray,
        promptText: PromptText,
    ): MaigBindResult<String> {
        val capabilityError = mapCapabilityToError(getBiometricCapability())
        if (capabilityError != null) {
            return MaigBindResult.Failure(capabilityError)
        }

        val initResult: MaigBindResult<Pair<PrivateKey, Signature>> =
            withContext(Dispatchers.IO) {
                val key =
                    keyStoreGateway.getPrivateKeyOrNull(alias)
                        ?: return@withContext MaigBindResult.Failure(MaigBindError.NotEnrolled(accountId))
                try {
                    val sig = signatureFactory()
                    sig.initSign(key)
                    MaigBindResult.Success(key to sig)
                } catch (ex: Exception) {
                    if (ex is KeyPermanentlyInvalidatedException) {
                        clearInvalidatedAlias(accountId, alias)
                    }
                    MaigBindResult.Failure(mapPlatformException(ex))
                }
            }

        val (privateKey, signature) =
            when (initResult) {
                is MaigBindResult.Failure -> return initResult
                is MaigBindResult.Success -> initResult.value
            }

        check(privateKey.algorithm.isNotEmpty())
        val promptOutcome =
            biometricLauncher.authenticate(
                activity = activity,
                title = promptText.title,
                subtitle = promptText.subtitle,
                description = promptText.description,
                negativeButtonText = promptText.negativeButtonText,
                signature = signature,
            )

        return when (promptOutcome) {
            is BiometricPromptOutcome.Error ->
                MaigBindResult.Failure(mapBiometricError(promptOutcome.errorCode, promptOutcome.message))
            is BiometricPromptOutcome.Succeeded -> {
                // Defense-in-depth reference identity check against simple callback hooks; the
                // authoritative enforcement is server-side ECDSA verification against the attested
                // hardware key that KeyMint/StrongBox only unlocks with a hardware AuthToken.
                val returnedSig = promptOutcome.returnedSignature
                if (returnedSig == null || returnedSig !== signature) {
                    return MaigBindResult.Failure(
                        MaigBindError.CryptoObjectTampered(
                            "AuthenticationResult CryptoObject signature was null or replaced",
                        ),
                    )
                }
                try {
                    val derSignature =
                        withContext(Dispatchers.Default) {
                            returnedSig.update(signingInput)
                            returnedSig.sign()
                        }
                    MaigBindResult.Success(Base64Url.encode(derSignature))
                } catch (ex: Exception) {
                    if (ex is KeyPermanentlyInvalidatedException) {
                        clearInvalidatedAlias(accountId, alias)
                    }
                    MaigBindResult.Failure(mapPlatformException(ex))
                }
            }
        }
    }

    private fun resolveActiveAlias(accountId: String): String? =
        aliasSlotStore.getActiveAlias(saltedAccountHash(accountId))

    private fun saltedAccountHash(accountId: String): String {
        val salt = aliasSlotStore.getOrCreateInstallSalt()
        return accountHash(accountId, salt)
    }

    private fun clearInvalidatedAlias(
        accountId: String,
        alias: String,
    ) {
        val hash = saltedAccountHash(accountId)
        runCatching { keyStoreGateway.deleteKey(alias) }
        if (aliasSlotStore.getActiveAlias(hash) == alias) aliasSlotStore.setActiveAlias(hash, null)
        if (aliasSlotStore.getPendingAlias(hash) == alias) aliasSlotStore.setPendingAlias(hash, null)
    }

    private fun mapCapabilityToError(capability: BiometricCapability): MaigBindError? =
        when (capability) {
            BiometricCapability.READY_STRONG -> null
            BiometricCapability.NONE_ENROLLED -> MaigBindError.BiometryNotEnrolled()
            BiometricCapability.HARDWARE_UNAVAILABLE ->
                MaigBindError.HardwareUnavailable("Biometric hardware temporarily unavailable")
            BiometricCapability.NO_HARDWARE,
            BiometricCapability.SECURITY_UPDATE_REQUIRED,
            BiometricCapability.UNSUPPORTED,
            ->
                MaigBindError.BiometryUnavailable()
        }

    private fun mapBiometricError(
        errorCode: Int,
        message: String,
    ): MaigBindError =
        when (errorCode) {
            BiometricPrompt.ERROR_CANCELED,
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            ->
                MaigBindError.Cancelled(errorCode = errorCode, message = message.ifBlank { "Authentication cancelled" })
            BiometricPrompt.ERROR_LOCKOUT ->
                MaigBindError.Lockout(isPermanent = false, message = message.ifBlank { "Biometric temporary lockout" })
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT ->
                MaigBindError.Lockout(isPermanent = true, message = message.ifBlank { "Biometric permanent lockout" })
            BiometricPrompt.ERROR_NO_BIOMETRICS ->
                MaigBindError.BiometryNotEnrolled()
            BiometricPrompt.ERROR_HW_NOT_PRESENT,
            BiometricPrompt.ERROR_HW_UNAVAILABLE,
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
            ->
                MaigBindError.BiometryUnavailable(reasonCode = errorCode, message = message)
            else ->
                MaigBindError.PlatformFailure(message = message.ifBlank { "Biometric error $errorCode" })
        }

    private fun mapPlatformException(ex: Throwable): MaigBindError =
        when (ex) {
            is KeyPermanentlyInvalidatedException -> MaigBindError.NeedsReEnrollment()
            is UserNotAuthenticatedException -> MaigBindError.UserNotAuthenticated()
            is StrongBoxUnavailableException ->
                MaigBindError.HardwareUnavailable(ex.message ?: "StrongBox unavailable")
            else ->
                MaigBindError.PlatformFailure(
                    message = ex.message ?: "Unexpected keystore error",
                    causeName = ex::class.simpleName,
                )
        }

    internal companion object {
        fun accountHash(
            accountId: String,
            installSalt: ByteArray,
        ): String {
            val idBytes = accountId.encodeToByteArray()
            val input = ByteArray(installSalt.size + idBytes.size)
            installSalt.copyInto(input, destinationOffset = 0)
            idBytes.copyInto(input, destinationOffset = installSalt.size)
            return Sha256.digest(input).toHexString().take(24)
        }

        fun freshAliasFor(accountHash: String): String = "maigbind:$accountHash:${UUID.randomUUID().toString().take(8)}"
    }
}
