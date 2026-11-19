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
 * Generates non-exportable EC P-256 keys in StrongBox/TEE under SHA-256 hashed aliases (no PII in
 * `AndroidKeyStore`), bound to `BIOMETRIC_STRONG` per-use authentication (`CryptoObject`), and
 * signs canonical CBOR payloads for server-side verification.
 *
 * Re-enrollment safety:
 * - If an active key already exists for an account, [enroll] stages the replacement key in a
 *   pending alias without destroying the active key. After the server confirms `ACTIVE` for Step 2,
 *   call [activatePendingEnrollment] to promote the pending key and purge the superseded one (or
 *   [abortPendingEnrollment] if enrollment fails/cancels).
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

    /** Returns `true` if an active hardware key already exists for [accountId]. */
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

    /** Returns the `keyId` of a staged-but-unactivated pending re-enrollment key, if any. */
    public suspend fun getPendingKeyId(accountId: String): String? =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) return@withContext null
            val alias = aliasSlotStore.getPendingAlias(accountHash(accountId)) ?: return@withContext null
            keyStoreGateway.getPublicKeySpkiOrNull(alias)?.let(::computeKeyId)
        }

    /**
     * Step 1 of enrollment: generates a non-exportable EC P-256 hardware key for [accountId]
     * bound to [serverChallengeBase64Url] and returns the public key + X.509 attestation chain.
     *
     * If an active key already exists for [accountId], the new key is staged under a temporary
     * pending alias so the existing key remains usable until [activatePendingEnrollment] is called.
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

            val hash = accountHash(accountId)
            val existingActive =
                resolveActiveAlias(
                    accountId,
                )?.takeIf { keyStoreGateway.getPrivateKeyOrNull(it) != null }
            val newAlias = freshAliasFor(hash)

            return@withContext try {
                val material =
                    keyStoreGateway.generateHardwareKey(
                        alias = newAlias,
                        attestationChallenge = challengeBytes,
                        config = config,
                    )
                if (existingActive == null) {
                    aliasSlotStore.setActiveAlias(hash, newAlias)
                } else {
                    // Clean up any stale unpromoted pending key before staging the new one.
                    aliasSlotStore.getPendingAlias(hash)?.let { oldPending ->
                        if (oldPending != existingActive) runCatching { keyStoreGateway.deleteKey(oldPending) }
                    }
                    aliasSlotStore.setPendingAlias(hash, newAlias)
                }
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
     * Step 2 of enrollment: signs the server-issued `popChallenge` with the newly attested key
     * (staged pending key if re-enrolling, or active key on first enrollment) using
     * `BiometricPrompt` + `CryptoObject(Signature)`.
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
        val hash = accountHash(accountId)
        val targetAlias =
            aliasSlotStore.getPendingAlias(hash)
                ?: resolveActiveAlias(accountId)
                ?: return MaigBindResult.Failure(MaigBindError.NotEnrolled(accountId))
        val spki =
            withContext(Dispatchers.IO) { keyStoreGateway.getPublicKeySpkiOrNull(targetAlias) }
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
            val signed = signBytesWithAlias(activity, accountId, targetAlias, popPayload.signingInput(), promptText)
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
     * Promotes the staged pending key to active for [accountId] after the server confirms
     * `EnrollmentStatus.ACTIVE`, and deletes the superseded active key from `AndroidKeyStore`.
     */
    public suspend fun activatePendingEnrollment(accountId: String): MaigBindResult<Unit> =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) {
                return@withContext MaigBindResult.Failure(MaigBindError.InvalidInput("accountId must not be blank"))
            }
            val hash = accountHash(accountId)
            val pending = aliasSlotStore.getPendingAlias(hash) ?: return@withContext MaigBindResult.Success(Unit)
            val previousActive = aliasSlotStore.getActiveAlias(hash)
            aliasSlotStore.setActiveAlias(hash, pending)
            aliasSlotStore.setPendingAlias(hash, null)
            if (previousActive != null && previousActive != pending) {
                runCatching { keyStoreGateway.deleteKey(previousActive) }
            }
            MaigBindResult.Success(Unit)
        }

    /**
     * Deletes any unactivated pending re-enrollment key for [accountId], leaving the prior active
     * key intact.
     */
    public suspend fun abortPendingEnrollment(accountId: String): MaigBindResult<Unit> =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) {
                return@withContext MaigBindResult.Failure(MaigBindError.InvalidInput("accountId must not be blank"))
            }
            val hash = accountHash(accountId)
            val pending = aliasSlotStore.getPendingAlias(hash)
            aliasSlotStore.setPendingAlias(hash, null)
            if (pending != null) {
                runCatching { keyStoreGateway.deleteKey(pending) }
            }
            MaigBindResult.Success(Unit)
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
                val hash = accountHash(accountId)
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

    private fun resolveActiveAlias(accountId: String): String? = aliasSlotStore.getActiveAlias(accountHash(accountId))

    private fun clearInvalidatedAlias(
        accountId: String,
        alias: String,
    ) {
        val hash = accountHash(accountId)
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
        fun accountHash(accountId: String): String = Sha256.digest(accountId.encodeToByteArray()).toHexString().take(24)

        fun freshAliasFor(accountHash: String): String = "maigbind:$accountHash:${UUID.randomUUID().toString().take(8)}"
    }
}
