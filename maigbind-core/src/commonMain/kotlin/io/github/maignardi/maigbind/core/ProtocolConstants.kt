package io.github.maignardi.maigbind.core

import kotlinx.serialization.Serializable

/**
 * Current MaigBind protocol version.
 */
public const val MAIGBIND_PROTOCOL_VERSION: Int = 1

/**
 * Domain separation tags prepended to canonical CBOR bytes before ECDSA signing.
 *
 * The signing input format is strictly:
 * `ASCII(tag) || 0x00 || deterministicCbor(payload)`.
 *
 * This guarantees that signatures produced in one protocol context (e.g., enrollment
 * proof-of-possession) can never validate in another context (e.g., transaction execution).
 */
public enum class DomainTag(
    public val tag: String,
) {
    /** Domain tag for enrollment Proof-of-Possession signatures. */
    ENROLL_POP("MaigBind/v1/enroll-pop"),

    /** Domain tag for sensitive operation / transaction signatures. */
    TRANSACTION("MaigBind/v1/tx"),
    ;

    /**
     * Prepends this domain tag and a `0x00` separator byte to [cborBytes].
     */
    public fun wrap(cborBytes: ByteArray): ByteArray {
        val prefix = tag.encodeToByteArray()
        val out = ByteArray(prefix.size + 1 + cborBytes.size)
        prefix.copyInto(out, destinationOffset = 0)
        out[prefix.size] = 0x00
        cborBytes.copyInto(out, destinationOffset = prefix.size + 1)
        return out
    }
}

/**
 * Indicates which hardware isolation environment backs the private signing key.
 */
@Serializable
public enum class SecurityBacking {
    /** Dedicated hardware security module (Android StrongBox Keymaster/KeyMint). */
    STRONGBOX,

    /** Trusted Execution Environment (Android TEE Keymaster/KeyMint). */
    TEE,

    /** Apple Secure Enclave (Phase 2 iOS). */
    SECURE_ENCLAVE,

    /** Unknown or unverified backing (rejected by default server policy). */
    UNKNOWN,
}

/**
 * Indicates the biometric authentication policy enforced during signing.
 */
@Serializable
public enum class AuthPolicyUsed {
    /** Hardware-backed Class 3 strong biometrics (`BIOMETRIC_STRONG` / `.biometryCurrentSet`). */
    BIOMETRIC_STRONG,

    /**
     * Weak biometrics explicitly opted into by the caller.
     * Rejected by default `VerificationPolicy` unless explicitly permitted.
     */
    BIOMETRIC_WEAK_OPT_IN,
}

/**
 * Human-readable transaction summary displayed in the OS biometric confirmation prompt.
 *
 * Note: Android Protected Confirmation (`ConfirmationPrompt`) was deprecated/abandoned due to
 * low device adoption; MaigBind displays clear transaction metadata in `BiometricPrompt.PromptInfo`
 * while enforcing payload integrity cryptographically on the server.
 */
@Serializable
public data class PromptText(
    val title: String,
    val subtitle: String? = null,
    val description: String? = null,
    val negativeButtonText: String = "Cancel",
) {
    init {
        require(title.isNotBlank()) { "Prompt title must not be blank" }
        require(negativeButtonText.isNotBlank()) { "Negative button text must not be blank" }
    }
}
