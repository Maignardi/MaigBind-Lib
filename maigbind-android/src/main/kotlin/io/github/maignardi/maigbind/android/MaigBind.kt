package io.github.maignardi.maigbind.android

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.github.maignardi.maigbind.core.AuthPolicyUsed
import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.ClientAuthMetadata
import io.github.maignardi.maigbind.core.EnrollmentConfirmRequest
import io.github.maignardi.maigbind.core.EnrollmentPoPPayload
import io.github.maignardi.maigbind.core.EnrollmentRequest
import io.github.maignardi.maigbind.core.MaigBindError
import io.github.maignardi.maigbind.core.MaigBindResult
import io.github.maignardi.maigbind.core.PromptText
import io.github.maignardi.maigbind.core.SecurityBacking
import io.github.maignardi.maigbind.core.SignedPayload
import io.github.maignardi.maigbind.core.TransactionPayload
import io.github.maignardi.maigbind.core.computeKeyId
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.PrivateKey
import java.security.Signature

/**
 * Android client SDK for MaigBind.
 *
 * Generates non-exportable EC P-256 keys in StrongBox/TEE bound to `BIOMETRIC_STRONG` per-use
 * authentication, validates `BiometricPrompt` `CryptoObject` reference identity against runtime
 * Frida hooks, and signs canonical CBOR payloads without making client-side trust decisions.
 *
 * Security hygiene:
 * - Never logs key material, challenges, signatures, or transaction payloads.
 * - Never leaks Android Keystore `PrivateKey` or `KeyStore` types in the public API.
 * - Exposes all failure modes as typed [MaigBindError] instances inside [MaigBindResult].
 */
public class MaigBind internal constructor(
    private val config: MaigBindConfig,
    private val keyStoreGateway: AndroidKeyStoreGateway,
    private val biometricLauncher: BiometricPromptLauncher,
    private val signatureFactory: () -> Signature = { Signature.getInstance("SHA256withECDSA") },
) {
    /**
     * Creates a [MaigBind] instance backed by AndroidKeyStore and `androidx.biometric.BiometricPrompt`.
     */
    public constructor(
        context: Context,
        config: MaigBindConfig = MaigBindConfig(),
    ) : this(
        config = config,
        keyStoreGateway = PlatformAndroidKeyStoreGateway(),
        biometricLauncher = PlatformBiometricPromptLauncher(context.applicationContext),
    )

    /**
     * Checks whether strong biometric authentication is available and enrolled on this device.
     */
    public fun getBiometricCapability(): BiometricCapability =
        biometricLauncher.checkCapability(config.allowWeakBiometricFallback)

    /**
     * Returns `true` if a hardware key alias already exists for [accountId].
     */
    public suspend fun hasEnrolledKey(accountId: String): Boolean =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) return@withContext false
            keyStoreGateway.getPrivateKeyOrNull(keyAlias(accountId)) != null
        }

    /**
     * Returns the deterministic `keyId` (`base64url(SHA-256(spki))`) for [accountId] if enrolled.
     */
    public suspend fun getEnrolledKeyId(accountId: String): String? =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) return@withContext null
            keyStoreGateway.getPublicKeySpkiOrNull(keyAlias(accountId))?.let(::computeKeyId)
        }

    /**
     * Step 1 of enrollment: generates a non-exportable EC P-256 hardware key for [accountId]
     * bound to [serverChallengeBase64Url] and returns the public key + X.509 attestation chain.
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

            val capabilityError = checkBiometryPrecondition()
            if (capabilityError != null) {
                return@withContext MaigBindResult.Failure(capabilityError)
            }

            return@withContext try {
                val material =
                    keyStoreGateway.generateHardwareKey(
                        alias = keyAlias(accountId),
                        attestationChallenge = challengeBytes,
                        config = config,
                    )
                val keyId = computeKeyId(material.publicKeySpkiDer)
                MaigBindResult.Success(
                    EnrollmentRequest(
                        accountId = accountId,
                        keyId = keyId,
                        publicKeySpkiBase64Url = Base64Url.encode(material.publicKeySpkiDer),
                        attestationChainBase64Url = material.attestationChainDer.map { Base64Url.encode(it) },
                        challengeBase64Url = serverChallengeBase64Url,
                        securityBacking = material.securityBacking,
                        authPolicyUsed = resolveAuthPolicy(getBiometricCapability()),
                    ),
                )
            } catch (ex: StrongBoxUnavailableException) {
                MaigBindResult.Failure(
                    MaigBindError.HardwareUnavailable(ex.message ?: "StrongBox unavailable"),
                )
            } catch (ex: Exception) {
                MaigBindResult.Failure(mapPlatformException(ex))
            }
        }

    /**
     * Step 2 of enrollment: signs the server-issued `popChallenge` with the newly attested key
     * using `BiometricPrompt` + `CryptoObject(Signature)` before the server activates the binding.
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
        val keyId =
            getEnrolledKeyId(accountId)
                ?: return MaigBindResult.Failure(MaigBindError.NotEnrolled(accountId))

        val popPayload =
            EnrollmentPoPPayload(
                keyId = keyId,
                accountId = accountId,
                challenge = popChallengeBase64Url,
                issuedAt = issuedAt,
                expiresAt = expiresAt,
            )

        return when (val signed = signBytesWithBiometrics(activity, accountId, popPayload.signingInput(), promptText)) {
            is MaigBindResult.Failure -> signed
            is MaigBindResult.Success ->
                MaigBindResult.Success(
                    EnrollmentConfirmRequest(
                        bindingId = bindingId,
                        popPayload = popPayload,
                        signatureBase64Url = signed.value.signatureBase64Url,
                        authMetadata = signed.value.authMetadata,
                    ),
                )
        }
    }

    /**
     * Prompts the user with `BiometricPrompt` (`BIOMETRIC_STRONG` + `CryptoObject(Signature)`)
     * displaying [promptText], and signs the canonical [payload] bytes.
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
        val enrolledKeyId =
            getEnrolledKeyId(accountId)
                ?: return MaigBindResult.Failure(MaigBindError.NotEnrolled(accountId))
        if (payload.keyId != enrolledKeyId) {
            return MaigBindResult.Failure(
                MaigBindError.InvalidInput("TransactionPayload.keyId does not match enrolled key for '$accountId'"),
            )
        }

        return when (val signed = signBytesWithBiometrics(activity, accountId, payload.signingInput(), promptText)) {
            is MaigBindResult.Failure -> signed
            is MaigBindResult.Success ->
                MaigBindResult.Success(
                    SignedPayload(
                        payload = payload,
                        signatureBase64Url = signed.value.signatureBase64Url,
                        authMetadata = signed.value.authMetadata,
                    ),
                )
        }
    }

    /**
     * Deletes the enrolled hardware key for [accountId] from `AndroidKeyStore`.
     */
    public suspend fun unenroll(accountId: String): MaigBindResult<Unit> =
        withContext(Dispatchers.IO) {
            if (accountId.isBlank()) {
                return@withContext MaigBindResult.Failure(MaigBindError.InvalidInput("accountId must not be blank"))
            }
            return@withContext try {
                keyStoreGateway.deleteKey(keyAlias(accountId))
                MaigBindResult.Success(Unit)
            } catch (ex: Exception) {
                MaigBindResult.Failure(mapPlatformException(ex))
            }
        }

    private data class SignedBytesOutcome(
        val signatureBase64Url: String,
        val authMetadata: ClientAuthMetadata,
    )

    private suspend fun signBytesWithBiometrics(
        activity: FragmentActivity,
        accountId: String,
        signingInput: ByteArray,
        promptText: PromptText,
    ): MaigBindResult<SignedBytesOutcome> {
        val capability = getBiometricCapability()
        val capabilityError = mapCapabilityToError(capability)
        if (capabilityError != null) {
            return MaigBindResult.Failure(capabilityError)
        }

        val alias = keyAlias(accountId)
        val initResult: MaigBindResult<Triple<PrivateKey, SecurityBacking, Signature>> =
            withContext(Dispatchers.IO) {
                val key =
                    keyStoreGateway.getPrivateKeyOrNull(alias)
                        ?: return@withContext MaigBindResult.Failure(MaigBindError.NotEnrolled(accountId))
                val backing = keyStoreGateway.getKeySecurityBacking(alias, key)
                try {
                    val sig = signatureFactory()
                    sig.initSign(key)
                    MaigBindResult.Success(Triple(key, backing, sig))
                } catch (ex: Exception) {
                    if (ex is KeyPermanentlyInvalidatedException) {
                        runCatching { keyStoreGateway.deleteKey(alias) }
                    }
                    MaigBindResult.Failure(mapPlatformException(ex))
                }
            }

        val (privateKey, securityBacking, signature) =
            when (initResult) {
                is MaigBindResult.Failure -> return initResult
                is MaigBindResult.Success -> initResult.value
            }

        return executeSignWithInitialized(
            activity = activity,
            alias = alias,
            privateKey = privateKey,
            securityBacking = securityBacking,
            signature = signature,
            capability = capability,
            signingInput = signingInput,
            promptText = promptText,
        )
    }

    private suspend fun executeSignWithInitialized(
        activity: FragmentActivity,
        alias: String,
        privateKey: PrivateKey,
        securityBacking: SecurityBacking,
        signature: Signature,
        capability: BiometricCapability,
        signingInput: ByteArray,
        promptText: PromptText,
    ): MaigBindResult<SignedBytesOutcome> {
        // Keep parameter privateKey referenced for future diagnostic hooks without leaking key bytes.
        check(privateKey.algorithm.isNotEmpty())
        val authenticators =
            if (config.allowWeakBiometricFallback &&
                capability == BiometricCapability.READY_WEAK_ONLY
            ) {
                BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK
            } else {
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            }

        val promptOutcome =
            biometricLauncher.authenticate(
                activity = activity,
                title = promptText.title,
                subtitle = promptText.subtitle,
                description = promptText.description,
                negativeButtonText = promptText.negativeButtonText,
                authenticators = authenticators,
                signature = signature,
            )

        return when (promptOutcome) {
            is BiometricPromptOutcome.Error -> {
                MaigBindResult.Failure(mapBiometricError(promptOutcome.errorCode, promptOutcome.message))
            }
            is BiometricPromptOutcome.Succeeded -> {
                // Critical defense against Frida callback hooks (e.g., Universal Biometric Bypass):
                // verify non-null CryptoObject AND exact reference identity of the Signature instance.
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
                    MaigBindResult.Success(
                        SignedBytesOutcome(
                            signatureBase64Url = Base64Url.encode(derSignature),
                            authMetadata =
                                ClientAuthMetadata(
                                    securityBacking = securityBacking,
                                    authPolicyUsed = resolveAuthPolicy(capability),
                                ),
                        ),
                    )
                } catch (ex: Exception) {
                    if (ex is KeyPermanentlyInvalidatedException) {
                        runCatching { keyStoreGateway.deleteKey(alias) }
                    }
                    MaigBindResult.Failure(mapPlatformException(ex))
                }
            }
        }
    }

    private fun checkBiometryPrecondition(): MaigBindError? = mapCapabilityToError(getBiometricCapability())

    private fun mapCapabilityToError(capability: BiometricCapability): MaigBindError? =
        when (capability) {
            BiometricCapability.READY_STRONG -> null
            BiometricCapability.READY_WEAK_ONLY ->
                if (config.allowWeakBiometricFallback) {
                    null
                } else {
                    MaigBindError.BiometryUnavailable(
                        message = "Only weak biometrics available; BIOMETRIC_STRONG required",
                    )
                }
            BiometricCapability.NONE_ENROLLED -> MaigBindError.BiometryNotEnrolled()
            BiometricCapability.HARDWARE_UNAVAILABLE ->
                MaigBindError.HardwareUnavailable("Biometric hardware temporarily unavailable")
            BiometricCapability.NO_HARDWARE,
            BiometricCapability.SECURITY_UPDATE_REQUIRED,
            BiometricCapability.UNSUPPORTED,
            ->
                MaigBindError.BiometryUnavailable()
        }

    private fun resolveAuthPolicy(capability: BiometricCapability): AuthPolicyUsed =
        if (capability == BiometricCapability.READY_WEAK_ONLY && config.allowWeakBiometricFallback) {
            AuthPolicyUsed.BIOMETRIC_WEAK_OPT_IN
        } else {
            AuthPolicyUsed.BIOMETRIC_STRONG
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
        fun keyAlias(accountId: String): String = "maigbind:$accountId"
    }
}
