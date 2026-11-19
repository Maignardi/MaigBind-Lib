package io.github.maignardi.maigbind.verifier

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import java.security.cert.X509Certificate

/**
 * OID for the Android Key Attestation X.509 extension.
 * Reference: https://source.android.com/docs/security/features/keystore/attestation
 */
public const val KEY_ATTESTATION_OID: String = "1.3.6.1.4.1.11129.2.1.17"

/** Keymaster / KeyMint security levels from the AOSP attestation schema. */
public enum class AttestationSecurityLevel(
    public val code: Int,
) {
    SOFTWARE(0),
    TRUSTED_ENVIRONMENT(1),
    STRONG_BOX(2),
    ;

    public companion object {
        public fun fromCode(code: Int): AttestationSecurityLevel =
            entries.firstOrNull { it.code == code }
                ?: throw IllegalArgumentException("Unknown AttestationSecurityLevel code: $code")
    }
}

/** Hardware Verified Boot states from AOSP `RootOfTrust`. */
public enum class VerifiedBootState(
    public val code: Int,
) {
    VERIFIED(0),
    SELF_SIGNED(1),
    UNVERIFIED(2),
    FAILED(3),
    ;

    public companion object {
        public fun fromCode(code: Int): VerifiedBootState =
            entries.firstOrNull { it.code == code }
                ?: throw IllegalArgumentException("Unknown VerifiedBootState code: $code")
    }
}

/** `RootOfTrust` sequence from `AuthorizationList` tag `[704]`. */
public data class RootOfTrust(
    val verifiedBootKey: ByteArray,
    val deviceLocked: Boolean,
    val verifiedBootState: VerifiedBootState,
    val verifiedBootHash: ByteArray?,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RootOfTrust) return false
        return verifiedBootKey.contentEquals(other.verifiedBootKey) &&
            deviceLocked == other.deviceLocked &&
            verifiedBootState == other.verifiedBootState &&
            (verifiedBootHash?.contentEquals(other.verifiedBootHash) ?: (other.verifiedBootHash == null))
    }

    override fun hashCode(): Int {
        var result = verifiedBootKey.contentHashCode()
        result = 31 * result + deviceLocked.hashCode()
        result = 31 * result + verifiedBootState.hashCode()
        result = 31 * result + (verifiedBootHash?.contentHashCode() ?: 0)
        return result
    }
}

/** Single package entry inside `AttestationApplicationId` (`tag [709]`). */
public data class AttestationPackageInfo(
    val packageName: String,
    val version: Long,
)

/** Parsed `AttestationApplicationId` from `AuthorizationList` tag `[709]`. */
public data class AttestationApplicationId(
    val packages: List<AttestationPackageInfo>,
    val signatureDigests: List<ByteArray>,
)

/** Parsed `AuthorizationList` tags relevant to MaigBind verification. */
public data class AuthorizationList(
    val purposes: Set<Int> = emptySet(),
    val algorithm: Int? = null,
    val keySize: Int? = null,
    val digests: Set<Int> = emptySet(),
    val ecCurve: Int? = null,
    val noAuthRequired: Boolean = false,
    val userAuthType: Long? = null,
    val authTimeoutSeconds: Long? = null,
    val unlockedDeviceRequired: Boolean = false,
    val rootOfTrust: RootOfTrust? = null,
    val osVersion: Int? = null,
    val osPatchLevel: Int? = null,
    val attestationApplicationId: AttestationApplicationId? = null,
    val vendorPatchLevel: Int? = null,
    val bootPatchLevel: Int? = null,
)

/** Parsed AOSP `KeyDescription` attestation extension (`OID 1.3.6.1.4.1.11129.2.1.17`). */
public data class AttestationRecord(
    val attestationVersion: Int,
    val attestationSecurityLevel: AttestationSecurityLevel,
    val keymasterVersion: Int,
    val keymasterSecurityLevel: AttestationSecurityLevel,
    val attestationChallenge: ByteArray,
    val uniqueId: ByteArray,
    val softwareEnforced: AuthorizationList,
    val hardwareEnforced: AuthorizationList,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttestationRecord) return false
        return attestationVersion == other.attestationVersion &&
            attestationSecurityLevel == other.attestationSecurityLevel &&
            keymasterVersion == other.keymasterVersion &&
            keymasterSecurityLevel == other.keymasterSecurityLevel &&
            attestationChallenge.contentEquals(other.attestationChallenge) &&
            uniqueId.contentEquals(other.uniqueId) &&
            softwareEnforced == other.softwareEnforced &&
            hardwareEnforced == other.hardwareEnforced
    }

    override fun hashCode(): Int {
        var result = attestationVersion
        result = 31 * result + attestationSecurityLevel.hashCode()
        result = 31 * result + keymasterVersion
        result = 31 * result + keymasterSecurityLevel.hashCode()
        result = 31 * result + attestationChallenge.contentHashCode()
        result = 31 * result + uniqueId.contentHashCode()
        result = 31 * result + softwareEnforced.hashCode()
        result = 31 * result + hardwareEnforced.hashCode()
        return result
    }
}

/**
 * Parses AOSP `KeyDescription` extensions (`OID 1.3.6.1.4.1.11129.2.1.17`) from X.509 certificates.
 *
 * Schema reference: https://source.android.com/docs/security/features/keystore/attestation#schema
 */
public object KeyAttestationParser {
    public const val KM_PURPOSE_SIGN: Int = 2
    public const val KM_ALGORITHM_EC: Int = 3
    public const val KM_EC_CURVE_P_256: Int = 1
    public const val KM_DIGEST_SHA_2_256: Int = 4
    public const val HW_AUTH_PASSWORD: Long = 1L
    public const val HW_AUTH_BIOMETRIC: Long = 2L

    private const val TAG_PURPOSE = 1
    private const val TAG_ALGORITHM = 2
    private const val TAG_KEY_SIZE = 3
    private const val TAG_DIGEST = 5
    private const val TAG_EC_CURVE = 10
    private const val TAG_NO_AUTH_REQUIRED = 503
    private const val TAG_USER_AUTH_TYPE = 504
    private const val TAG_AUTH_TIMEOUT = 505
    private const val TAG_UNLOCKED_DEVICE_REQUIRED = 509
    private const val TAG_ROOT_OF_TRUST = 704
    private const val TAG_OS_VERSION = 705
    private const val TAG_OS_PATCH_LEVEL = 706
    private const val TAG_ATTESTATION_APPLICATION_ID = 709
    private const val TAG_VENDOR_PATCH_LEVEL = 718
    private const val TAG_BOOT_PATCH_LEVEL = 719

    /**
     * Extracts and parses the Android Key Attestation extension from [certificate], or returns
     * `null` if the extension is not present.
     *
     * @throws IllegalArgumentException if the extension is present but malformed.
     */
    public fun parseOrNull(certificate: X509Certificate): AttestationRecord? {
        val rawExtension = certificate.getExtensionValue(KEY_ATTESTATION_OID) ?: return null
        val octetString =
            ASN1InputStream(rawExtension).use { it.readObject() } as? ASN1OctetString
                ?: throw IllegalArgumentException("Attestation extension is not an OCTET STRING")
        val rootSeq =
            ASN1InputStream(octetString.octets).use { it.readObject() } as? ASN1Sequence
                ?: throw IllegalArgumentException("KeyDescription is not an ASN.1 SEQUENCE")
        return parseKeyDescription(rootSeq)
    }

    internal fun parseKeyDescription(seq: ASN1Sequence): AttestationRecord {
        require(seq.size() >= 8) { "KeyDescription must contain 8 elements, found ${seq.size()}" }
        val attestationVersion = (seq.getObjectAt(0) as ASN1Integer).intValueExact()
        val attestationSecurityLevel =
            AttestationSecurityLevel.fromCode(
                (seq.getObjectAt(1) as ASN1Enumerated).intValueExact(),
            )
        val keymasterVersion = (seq.getObjectAt(2) as ASN1Integer).intValueExact()
        val keymasterSecurityLevel =
            AttestationSecurityLevel.fromCode(
                (seq.getObjectAt(3) as ASN1Enumerated).intValueExact(),
            )
        val challenge = (seq.getObjectAt(4) as ASN1OctetString).octets
        val uniqueId = (seq.getObjectAt(5) as ASN1OctetString).octets
        val softwareEnforced = parseAuthorizationList(seq.getObjectAt(6) as ASN1Sequence)
        val hardwareEnforced = parseAuthorizationList(seq.getObjectAt(7) as ASN1Sequence)

        return AttestationRecord(
            attestationVersion = attestationVersion,
            attestationSecurityLevel = attestationSecurityLevel,
            keymasterVersion = keymasterVersion,
            keymasterSecurityLevel = keymasterSecurityLevel,
            attestationChallenge = challenge,
            uniqueId = uniqueId,
            softwareEnforced = softwareEnforced,
            hardwareEnforced = hardwareEnforced,
        )
    }

    private fun parseAuthorizationList(seq: ASN1Sequence): AuthorizationList {
        val state = AuthListState()
        for (element in seq) {
            val tagged =
                element as? ASN1TaggedObject
                    ?: throw IllegalArgumentException("AuthorizationList element is not tagged: $element")
            val obj = tagged.baseObject.toASN1Primitive()
            state.applyTag(tagged.tagNo, obj)
        }
        return state.build()
    }

    private class AuthListState {
        private var purposes = emptySet<Int>()
        private var algorithm: Int? = null
        private var keySize: Int? = null
        private var digests = emptySet<Int>()
        private var ecCurve: Int? = null
        private var noAuthRequired = false
        private var userAuthType: Long? = null
        private var authTimeoutSeconds: Long? = null
        private var unlockedDeviceRequired = false
        private var rootOfTrust: RootOfTrust? = null
        private var osVersion: Int? = null
        private var osPatchLevel: Int? = null
        private var attestationApplicationId: AttestationApplicationId? = null
        private var vendorPatchLevel: Int? = null
        private var bootPatchLevel: Int? = null

        fun applyTag(
            tagNo: Int,
            obj: ASN1Primitive,
        ) {
            if (tagNo < 500) {
                applyKeyTag(tagNo, obj)
            } else {
                applySystemTag(tagNo, obj)
            }
        }

        private fun applyKeyTag(
            tagNo: Int,
            obj: ASN1Primitive,
        ) {
            when (tagNo) {
                TAG_PURPOSE -> purposes = parseIntSet(obj)
                TAG_ALGORITHM -> algorithm = (obj as ASN1Integer).intValueExact()
                TAG_KEY_SIZE -> keySize = (obj as ASN1Integer).intValueExact()
                TAG_DIGEST -> digests = parseIntSet(obj)
                TAG_EC_CURVE -> ecCurve = (obj as ASN1Integer).intValueExact()
            }
        }

        private fun applySystemTag(
            tagNo: Int,
            obj: ASN1Primitive,
        ) {
            when (tagNo) {
                TAG_NO_AUTH_REQUIRED -> noAuthRequired = true
                TAG_USER_AUTH_TYPE -> userAuthType = (obj as ASN1Integer).longValueExact()
                TAG_AUTH_TIMEOUT -> authTimeoutSeconds = (obj as ASN1Integer).longValueExact()
                TAG_UNLOCKED_DEVICE_REQUIRED -> unlockedDeviceRequired = true
                TAG_ROOT_OF_TRUST -> rootOfTrust = parseRootOfTrust(obj as ASN1Sequence)
                TAG_OS_VERSION -> osVersion = (obj as ASN1Integer).intValueExact()
                TAG_OS_PATCH_LEVEL -> osPatchLevel = (obj as ASN1Integer).intValueExact()
                TAG_ATTESTATION_APPLICATION_ID -> {
                    attestationApplicationId = parseAttestationApplicationId((obj as ASN1OctetString).octets)
                }
                TAG_VENDOR_PATCH_LEVEL -> vendorPatchLevel = (obj as ASN1Integer).intValueExact()
                TAG_BOOT_PATCH_LEVEL -> bootPatchLevel = (obj as ASN1Integer).intValueExact()
            }
        }

        fun build(): AuthorizationList =
            AuthorizationList(
                purposes = purposes,
                algorithm = algorithm,
                keySize = keySize,
                digests = digests,
                ecCurve = ecCurve,
                noAuthRequired = noAuthRequired,
                userAuthType = userAuthType,
                authTimeoutSeconds = authTimeoutSeconds,
                unlockedDeviceRequired = unlockedDeviceRequired,
                rootOfTrust = rootOfTrust,
                osVersion = osVersion,
                osPatchLevel = osPatchLevel,
                attestationApplicationId = attestationApplicationId,
                vendorPatchLevel = vendorPatchLevel,
                bootPatchLevel = bootPatchLevel,
            )
    }

    private fun parseIntSet(obj: ASN1Primitive): Set<Int> {
        val set = obj as? ASN1Set ?: throw IllegalArgumentException("Expected ASN1Set, found $obj")
        val out = LinkedHashSet<Int>(set.size())
        for (item in set) {
            out.add((item as ASN1Integer).intValueExact())
        }
        return out
    }

    private fun parseRootOfTrust(seq: ASN1Sequence): RootOfTrust {
        require(seq.size() >= 3) { "RootOfTrust must have at least 3 fields" }
        val verifiedBootKey = (seq.getObjectAt(0) as ASN1OctetString).octets
        val deviceLocked = (seq.getObjectAt(1) as ASN1Boolean).isTrue
        val verifiedBootState =
            VerifiedBootState.fromCode(
                (seq.getObjectAt(2) as ASN1Enumerated).intValueExact(),
            )
        val verifiedBootHash =
            if (seq.size() >= 4) {
                (seq.getObjectAt(3) as ASN1OctetString).octets
            } else {
                null
            }
        return RootOfTrust(
            verifiedBootKey = verifiedBootKey,
            deviceLocked = deviceLocked,
            verifiedBootState = verifiedBootState,
            verifiedBootHash = verifiedBootHash,
        )
    }

    private fun parseAttestationApplicationId(derBytes: ByteArray): AttestationApplicationId {
        val seq =
            ASN1InputStream(derBytes).use { it.readObject() } as? ASN1Sequence
                ?: throw IllegalArgumentException("AttestationApplicationId must be an ASN.1 SEQUENCE")
        require(seq.size() >= 2) { "AttestationApplicationId must have packageInfos and signatureDigests" }
        val packageSet = seq.getObjectAt(0) as ASN1Set
        val sigSet = seq.getObjectAt(1) as ASN1Set

        val packages = ArrayList<AttestationPackageInfo>(packageSet.size())
        for (entry in packageSet) {
            val pkgSeq = entry as ASN1Sequence
            val name = (pkgSeq.getObjectAt(0) as ASN1OctetString).octets.decodeToString()
            val version = (pkgSeq.getObjectAt(1) as ASN1Integer).longValueExact()
            packages.add(AttestationPackageInfo(packageName = name, version = version))
        }

        val digests = ArrayList<ByteArray>(sigSet.size())
        for (entry in sigSet) {
            digests.add((entry as ASN1OctetString).octets)
        }
        return AttestationApplicationId(packages = packages, signatureDigests = digests)
    }
}
