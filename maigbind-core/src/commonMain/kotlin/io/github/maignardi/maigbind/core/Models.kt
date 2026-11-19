package io.github.maignardi.maigbind.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Closed algebraic representation of values allowed in canonical transaction fields.
 *
 * Floating-point types are intentionally excluded to prevent cross-platform representation
 * ambiguity; represent monetary amounts as integer minor units ([Int64]) or canonical decimal
 * strings ([Text]).
 */
@Serializable
public sealed class CanonicalValue {
    /** Converts this value into a canonical Kotlin value map/primitive for comparison. */
    public abstract fun contentEquals(other: CanonicalValue): Boolean

    @Serializable
    @SerialName("text")
    public data class Text(
        val value: String,
    ) : CanonicalValue() {
        override fun contentEquals(other: CanonicalValue): Boolean = other is Text && other.value == value
    }

    @Serializable
    @SerialName("int64")
    public data class Int64(
        val value: Long,
    ) : CanonicalValue() {
        override fun contentEquals(other: CanonicalValue): Boolean = other is Int64 && other.value == value
    }

    @Serializable
    @SerialName("bool")
    public data class Bool(
        val value: Boolean,
    ) : CanonicalValue() {
        override fun contentEquals(other: CanonicalValue): Boolean = other is Bool && other.value == value
    }

    @Serializable
    @SerialName("bytes")
    public class Bytes(
        public val value: ByteArray,
    ) : CanonicalValue() {
        override fun contentEquals(other: CanonicalValue): Boolean = other is Bytes && value.contentEquals(other.value)

        override fun equals(other: Any?): Boolean =
            this === other || (other is Bytes && value.contentEquals(other.value))

        override fun hashCode(): Int = value.contentHashCode()

        override fun toString(): String = "Bytes(${Base64Url.encode(value)})"
    }

    @Serializable
    @SerialName("list")
    public data class ListValue(
        val items: List<CanonicalValue>,
    ) : CanonicalValue() {
        override fun contentEquals(other: CanonicalValue): Boolean =
            other is ListValue &&
                items.size == other.items.size &&
                items.indices.all { idx -> items[idx].contentEquals(other.items[idx]) }
    }

    @Serializable
    @SerialName("map")
    public data class MapValue(
        val entries: Map<String, CanonicalValue>,
    ) : CanonicalValue() {
        override fun contentEquals(other: CanonicalValue): Boolean =
            other is MapValue &&
                entries.size == other.entries.size &&
                entries.all { (k, v) -> other.entries[k]?.let { v.contentEquals(it) } == true }
    }
}

/**
 * Helper to construct a [Map] of [CanonicalValue] entries ergonomically.
 */
public fun canonicalFields(vararg pairs: Pair<String, CanonicalValue>): Map<String, CanonicalValue> =
    linkedMapOf(*pairs)

/** Convenience factory for [CanonicalValue.Text]. */
public fun canonical(value: String): CanonicalValue.Text = CanonicalValue.Text(value)

/** Convenience factory for [CanonicalValue.Int64]. */
public fun canonical(value: Long): CanonicalValue.Int64 = CanonicalValue.Int64(value)

/** Convenience factory for [CanonicalValue.Int64] from an [Int]. */
public fun canonical(value: Int): CanonicalValue.Int64 = CanonicalValue.Int64(value.toLong())

/** Convenience factory for [CanonicalValue.Bool]. */
public fun canonical(value: Boolean): CanonicalValue.Bool = CanonicalValue.Bool(value)

/** Convenience factory for [CanonicalValue.Bytes]. */
public fun canonical(value: ByteArray): CanonicalValue.Bytes = CanonicalValue.Bytes(value)

/**
 * Canonical payload signed for every sensitive operation (e.g., bank transfer, limit change).
 */
@Serializable
public data class TransactionPayload(
    val protocolVersion: Int = MAIGBIND_PROTOCOL_VERSION,
    val keyId: String,
    val operationType: String,
    val nonce: String,
    val issuedAt: Long,
    val expiresAt: Long,
    val fields: Map<String, CanonicalValue> = emptyMap(),
) {
    init {
        require(protocolVersion == MAIGBIND_PROTOCOL_VERSION) {
            "Unsupported protocolVersion: $protocolVersion"
        }
        require(keyId.isNotBlank()) { "keyId must not be blank" }
        require(operationType.isNotBlank()) { "operationType must not be blank" }
        require(nonce.isNotBlank()) { "nonce must not be blank" }
        require(expiresAt >= issuedAt) { "expiresAt ($expiresAt) must be >= issuedAt ($issuedAt)" }
    }

    /**
     * Converts this payload to its [CanonicalValue.MapValue] representation and serializes it
     * using Deterministic CBOR (RFC 8949 §4.2).
     */
    public fun toCanonicalCborBytes(): ByteArray {
        val root =
            CanonicalValue.MapValue(
                mapOf(
                    "protocolVersion" to CanonicalValue.Int64(protocolVersion.toLong()),
                    "keyId" to CanonicalValue.Text(keyId),
                    "operationType" to CanonicalValue.Text(operationType),
                    "nonce" to CanonicalValue.Text(nonce),
                    "issuedAt" to CanonicalValue.Int64(issuedAt),
                    "expiresAt" to CanonicalValue.Int64(expiresAt),
                    "fields" to CanonicalValue.MapValue(fields),
                ),
            )
        return DeterministicCbor.encode(root)
    }

    /**
     * Returns the exact byte sequence signed by the hardware key, prefixed with
     * [DomainTag.TRANSACTION].
     */
    public fun signingInput(): ByteArray = DomainTag.TRANSACTION.wrap(toCanonicalCborBytes())

    public companion object {
        /**
         * Parses a [TransactionPayload] from deterministic CBOR bytes.
         */
        public fun fromCanonicalCborBytes(bytes: ByteArray): TransactionPayload {
            val root =
                DeterministicCbor.decode(bytes) as? CanonicalValue.MapValue
                    ?: throw IllegalArgumentException("TransactionPayload CBOR root must be a map")
            val entries = root.entries
            val protocolVersion =
                (entries["protocolVersion"] as? CanonicalValue.Int64)?.value?.toInt()
                    ?: throw IllegalArgumentException("Missing or invalid protocolVersion")
            val keyId =
                (entries["keyId"] as? CanonicalValue.Text)?.value
                    ?: throw IllegalArgumentException("Missing or invalid keyId")
            val operationType =
                (entries["operationType"] as? CanonicalValue.Text)?.value
                    ?: throw IllegalArgumentException("Missing or invalid operationType")
            val nonce =
                (entries["nonce"] as? CanonicalValue.Text)?.value
                    ?: throw IllegalArgumentException("Missing or invalid nonce")
            val issuedAt =
                (entries["issuedAt"] as? CanonicalValue.Int64)?.value
                    ?: throw IllegalArgumentException("Missing or invalid issuedAt")
            val expiresAt =
                (entries["expiresAt"] as? CanonicalValue.Int64)?.value
                    ?: throw IllegalArgumentException("Missing or invalid expiresAt")
            val fields =
                (entries["fields"] as? CanonicalValue.MapValue)?.entries
                    ?: throw IllegalArgumentException("Missing or invalid fields map")

            return TransactionPayload(
                protocolVersion = protocolVersion,
                keyId = keyId,
                operationType = operationType,
                nonce = nonce,
                issuedAt = issuedAt,
                expiresAt = expiresAt,
                fields = fields,
            )
        }
    }
}

/**
 * Canonical payload signed during Step 2 of enrollment to prove live biometric-unlocked
 * possession of the newly attested hardware private key.
 */
@Serializable
public data class EnrollmentPoPPayload(
    val protocolVersion: Int = MAIGBIND_PROTOCOL_VERSION,
    val keyId: String,
    val accountId: String,
    val challenge: String,
    val issuedAt: Long,
    val expiresAt: Long,
) {
    init {
        require(protocolVersion == MAIGBIND_PROTOCOL_VERSION) {
            "Unsupported protocolVersion: $protocolVersion"
        }
        require(keyId.isNotBlank()) { "keyId must not be blank" }
        require(accountId.isNotBlank()) { "accountId must not be blank" }
        require(challenge.isNotBlank()) { "challenge must not be blank" }
        require(expiresAt >= issuedAt) { "expiresAt ($expiresAt) must be >= issuedAt ($issuedAt)" }
    }

    /**
     * Serializes this Proof-of-Possession payload using Deterministic CBOR (RFC 8949 §4.2).
     */
    public fun toCanonicalCborBytes(): ByteArray {
        val root =
            CanonicalValue.MapValue(
                mapOf(
                    "protocolVersion" to CanonicalValue.Int64(protocolVersion.toLong()),
                    "keyId" to CanonicalValue.Text(keyId),
                    "accountId" to CanonicalValue.Text(accountId),
                    "challenge" to CanonicalValue.Text(challenge),
                    "issuedAt" to CanonicalValue.Int64(issuedAt),
                    "expiresAt" to CanonicalValue.Int64(expiresAt),
                ),
            )
        return DeterministicCbor.encode(root)
    }

    /**
     * Returns the exact byte sequence signed by the hardware key, prefixed with
     * [DomainTag.ENROLL_POP].
     */
    public fun signingInput(): ByteArray = DomainTag.ENROLL_POP.wrap(toCanonicalCborBytes())
}

/**
 * Client-produced cryptographic proof of a sensitive operation.
 *
 * Security-critical hardware properties (`securityBacking`, biometric auth enforcement, boot state)
 * are established exclusively from the server-stored attested [EnrollmentStatus.ACTIVE] binding —
 * never from unsigned client-supplied metadata.
 */
@Serializable
public data class SignedPayload(
    val payload: TransactionPayload,
    val signatureBase64Url: String,
)

/**
 * Step-1 enrollment payload sent by the client containing the generated public key and its
 * hardware attestation certificate chain.
 */
@Serializable
public data class EnrollmentRequest(
    val accountId: String,
    val keyId: String,
    val publicKeySpkiBase64Url: String,
    val attestationChainBase64Url: List<String>,
    val challengeBase64Url: String,
    val securityBacking: SecurityBacking,
)

/**
 * Step-2 enrollment payload proving immediate biometric-unlocked possession of the attested key.
 */
@Serializable
public data class EnrollmentConfirmRequest(
    val bindingId: String,
    val popPayload: EnrollmentPoPPayload,
    val signatureBase64Url: String,
)

/**
 * Lifecycle status of a device key binding on the server.
 */
@Serializable
public enum class EnrollmentStatus {
    /** Attestation succeeded; awaiting immediate Proof-of-Possession signature. */
    PENDING_POP,

    /** Attestation and Proof-of-Possession both verified; binding can sign transactions. */
    ACTIVE,

    /** Binding has been revoked or superseded. */
    REVOKED,
}

/**
 * Result returned by the server after Step 1 attestation validation.
 */
@Serializable
public data class EnrollmentAttestResponse(
    val bindingId: String,
    val keyId: String,
    val status: EnrollmentStatus,
    val popChallengeBase64Url: String,
    val popExpiresAt: Long,
    val verdict: VerificationVerdict,
)

/**
 * Result returned by the server after Step 2 Proof-of-Possession confirmation.
 */
@Serializable
public data class EnrollmentConfirmResponse(
    val bindingId: String,
    val keyId: String,
    val status: EnrollmentStatus,
    val verdict: VerificationVerdict,
)

/**
 * Overall verification outcome produced by `maigbind-verifier`.
 */
@Serializable
public enum class VerdictStatus {
    /** All cryptographic, attestation, freshness, and policy checks passed. */
    VERIFIED,

    /** Rejected due to policy configuration (e.g., min patch level, StrongBox required, weak auth). */
    REJECTED_POLICY,

    /** Rejected due to cryptographic mismatch, tampered payload, replay, or revocation signal. */
    REJECTED_FRAUD_SIGNAL,

    /** Validation infrastructure failure (e.g., Google CRL/root endpoint unreachable). */
    ERROR_VALIDATION_INFRA,
}

/**
 * Severity of an individual verification [Finding].
 */
@Serializable
public enum class FindingSeverity {
    INFO,
    WARNING,
    CRITICAL,
}

/**
 * Stable diagnostic codes emitted by `maigbind-verifier` for audit logs and risk engines.
 */
@Serializable
public enum class FindingCode {
    OK,
    CHALLENGE_INVALID_OR_EXPIRED,
    CERT_CHAIN_EMPTY,
    CERT_CHAIN_UNTRUSTED_ROOT,
    CERT_CHAIN_EXPIRED_OR_NOT_YET_VALID,
    CERT_CHAIN_INVALID_SIGNATURE,
    CERT_REVOKED_OR_SUSPENDED,
    ATTESTATION_EXTENSION_MISSING,
    ATTESTATION_EXTENSION_MALFORMED,
    ATTESTATION_CHALLENGE_MISMATCH,
    ATTESTATION_SECURITY_LEVEL_TOO_LOW,
    KEYMASTER_SECURITY_LEVEL_TOO_LOW,
    BOOTLOADER_UNLOCKED_OR_UNVERIFIED,
    KEY_PURPOSE_INVALID,
    KEY_ALGORITHM_OR_CURVE_INVALID,
    KEY_NO_AUTH_REQUIRED_PRESENT,
    KEY_AUTH_TYPE_NOT_BIOMETRIC,
    KEY_AUTH_TIMEOUT_NOT_PER_USE,
    OS_PATCH_LEVEL_TOO_LOW,
    APP_IDENTITY_MISMATCH,
    LEAF_PUBLIC_KEY_MISMATCH,
    KEY_ID_MISMATCH,
    FACTORY_KEY_NOT_ALLOWED,
    STRONGBOX_REQUIRED,
    SUSPICIOUS_KEYBOX_FANOUT,
    BINDING_NOT_FOUND_OR_INACTIVE,
    POP_CHALLENGE_INVALID_OR_EXPIRED,
    NONCE_REPLAYED_OR_UNKNOWN,
    PAYLOAD_EXPIRED_OR_FUTURE,
    SIGNATURE_INVALID,
    PAYLOAD_FIELD_MISMATCH,
    INFRA_TRUST_STORE_UNAVAILABLE,
    INFRA_REVOCATION_LIST_UNAVAILABLE,
    INFRA_FAIL_OPEN_APPLIED,
}

/**
 * Individual diagnostic item within a [VerificationVerdict].
 */
@Serializable
public data class Finding(
    val code: FindingCode,
    val severity: FindingSeverity,
    val message: String,
    val details: Map<String, String> = emptyMap(),
)

/**
 * Rich server-side verification verdict distinguishing cryptographic/fraud rejections from
 * validation infrastructure errors.
 */
@Serializable
public data class VerificationVerdict(
    val status: VerdictStatus,
    val keyId: String? = null,
    val securityBacking: SecurityBacking? = null,
    val isRkpChain: Boolean? = null,
    val findings: List<Finding> = emptyList(),
) {
    /** Convenience property that is `true` only when [status] is [VerdictStatus.VERIFIED]. */
    public val isVerified: Boolean get() = status == VerdictStatus.VERIFIED
}
