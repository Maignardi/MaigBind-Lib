package io.github.maignardi.maigbind.android

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
 * on API 31+ when permitted by the device; falls back if unsupported on either StrongBox or TEE.
 */
public data class MaigBindConfig(
    val preferStrongBox: Boolean = true,
    val requireStrongBox: Boolean = false,
    val includeDevicePropertiesAttestation: Boolean = false,
)

/** Current biometric hardware and enrollment status on the device. */
public enum class BiometricCapability {
    READY_STRONG,
    NONE_ENROLLED,
    HARDWARE_UNAVAILABLE,
    NO_HARDWARE,
    SECURITY_UPDATE_REQUIRED,
    UNSUPPORTED,
}

/** Result of reconciling local active/pending key slots with the server's active `keyIds`. */
public enum class ReconciliationOutcome {
    /** Local active key is present in the server's active `keyIds` set. */
    UP_TO_DATE,

    /** Local pending key matched an active `keyId` on the server and was atomically promoted. */
    PROMOTED_PENDING,

    /** Server reported active `keyIds`, none matching local active or pending keys; re-enrollment needed. */
    NEEDS_RE_ENROLLMENT,

    /**
     * Server explicitly confirmed zero active bindings; any stale local active slot was cleared
     * while preserving any staged pending enrollment.
     */
    NOT_ENROLLED,
}

/** Outcome of atomically promoting a staged pending alias to active. */
internal sealed class SlotPromotionResult {
    data class Promoted(
        val newActiveAlias: String,
        val previousActiveAlias: String?,
    ) : SlotPromotionResult()

    data object NothingPending : SlotPromotionResult()

    data object CommitFailed : SlotPromotionResult()
}

/** Key generation artifact returned by [AndroidKeyStoreGateway]. */
internal data class GeneratedKeyMaterial(
    val publicKeySpkiDer: ByteArray,
    val attestationChainDer: List<ByteArray>,
    val securityBacking: SecurityBacking,
)

/** Abstraction over AndroidKeyStore operations for clean unit testing and hardware isolation. */
internal interface AndroidKeyStoreGateway {
    /**
     * Derives a deterministic, non-reversible, app-local account hash using a non-exportable
     * `AndroidKeyStore` HMAC-SHA256 key so low-entropy IDs (e.g. national IDs/CPFs) cannot be
     * brute-forced offline from `SharedPreferences` alone.
     */
    fun computeAccountHash(accountId: String): String

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

/**
 * Tracks active and pending Keystore aliases per Keystore-HMAC-derived account hash using atomic
 * slot promotion (`commit()` in a single preference transaction on Android).
 */
internal interface KeyAliasSlotStore {
    fun getActiveAlias(accountHash: String): String?

    fun setActiveAlias(
        accountHash: String,
        alias: String?,
    ): Boolean

    fun getPendingAlias(accountHash: String): String?

    fun setPendingAlias(
        accountHash: String,
        alias: String?,
    ): Boolean

    /**
     * Atomically promotes the pending alias to active and clears the pending slot in a single
     * persistent `commit()` transaction, checking whether persistence succeeded before allowing the
     * caller to delete any superseded key.
     */
    fun promotePendingToActive(accountHash: String): SlotPromotionResult
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
    fun checkCapability(): BiometricCapability

    suspend fun authenticate(
        activity: androidx.fragment.app.FragmentActivity,
        title: String,
        subtitle: String?,
        description: String?,
        negativeButtonText: String,
        signature: Signature,
    ): BiometricPromptOutcome
}
