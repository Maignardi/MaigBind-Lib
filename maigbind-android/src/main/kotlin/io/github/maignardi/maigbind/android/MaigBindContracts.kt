package io.github.maignardi.maigbind.android

import io.github.maignardi.maigbind.core.AuthPolicyUsed
import io.github.maignardi.maigbind.core.SecurityBacking
import java.security.PrivateKey
import java.security.Signature

/**
 * Configuration options for [MaigBind].
 *
 * @property preferStrongBox Attempt StrongBox-backed key generation on API 28+ with automatic
 * fallback to TEE on `StrongBoxUnavailableException` unless [requireStrongBox] is `true`.
 * @property requireStrongBox If `true`, fail with `HardwareUnavailable` instead of falling back
 * to TEE when StrongBox is unavailable.
 * @property includeDevicePropertiesAttestation Requests `setDevicePropertiesAttestationIncluded(true)`
 * on API 31+ when permitted by the device; falls back if unsupported unless strict.
 * @property allowWeakBiometricFallback Allows `BIOMETRIC_WEAK` if explicitly requested by policy.
 * Defaults to `false` (strict `BIOMETRIC_STRONG` only). Never allows `DEVICE_CREDENTIAL` fallback.
 */
public data class MaigBindConfig(
    val preferStrongBox: Boolean = true,
    val requireStrongBox: Boolean = false,
    val includeDevicePropertiesAttestation: Boolean = false,
    val allowWeakBiometricFallback: Boolean = false,
)

/** Current biometric hardware and enrollment status on the device. */
public enum class BiometricCapability {
    READY_STRONG,
    READY_WEAK_ONLY,
    NONE_ENROLLED,
    HARDWARE_UNAVAILABLE,
    NO_HARDWARE,
    SECURITY_UPDATE_REQUIRED,
    UNSUPPORTED,
}

/** Key generation artifact returned by [AndroidKeyStoreGateway]. */
internal data class GeneratedKeyMaterial(
    val publicKeySpkiDer: ByteArray,
    val attestationChainDer: List<ByteArray>,
    val securityBacking: SecurityBacking,
)

/** Abstraction over AndroidKeyStore operations for clean unit testing and hardware isolation. */
internal interface AndroidKeyStoreGateway {
    fun generateHardwareKey(
        alias: String,
        attestationChallenge: ByteArray,
        config: MaigBindConfig,
    ): GeneratedKeyMaterial

    fun getPrivateKeyOrNull(alias: String): PrivateKey?

    fun getPublicKeySpkiOrNull(alias: String): ByteArray?

    fun getKeySecurityBacking(
        alias: String,
        privateKey: PrivateKey,
    ): SecurityBacking

    fun deleteKey(alias: String)
}

/** Result delivered by [BiometricPromptLauncher] after displaying the OS biometric prompt. */
internal sealed class BiometricPromptOutcome {
    data class Succeeded(
        val returnedSignature: Signature?,
    ) : BiometricPromptOutcome()

    data class Error(
        val errorCode: Int,
        val message: String,
    ) : BiometricPromptOutcome()
}

/** Abstraction over `androidx.biometric.BiometricPrompt` for testable callback/CryptoObject verification. */
internal interface BiometricPromptLauncher {
    fun checkCapability(allowWeak: Boolean): BiometricCapability

    suspend fun authenticate(
        activity: androidx.fragment.app.FragmentActivity,
        title: String,
        subtitle: String?,
        description: String?,
        negativeButtonText: String,
        authenticators: Int,
        signature: Signature,
    ): BiometricPromptOutcome

    fun expectedAuthPolicy(allowWeak: Boolean): AuthPolicyUsed =
        if (allowWeak) AuthPolicyUsed.BIOMETRIC_WEAK_OPT_IN else AuthPolicyUsed.BIOMETRIC_STRONG
}
