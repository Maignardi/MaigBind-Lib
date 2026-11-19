package io.github.maignardi.maigbind.verifier

import io.github.maignardi.maigbind.core.Base64Url

/**
 * Controls how `maigbind-verifier` behaves when external validation infrastructure (such as the
 * Google root trust feed or revocation list) is unavailable.
 */
public enum class FailMode {
    /**
     * Reject validation with [io.github.maignardi.maigbind.core.VerdictStatus.ERROR_VALIDATION_INFRA]
     * (recommended for production).
     */
    FAIL_CLOSED,

    /** Allow operation to proceed while emitting a critical audit finding ([INFRA_FAIL_OPEN_APPLIED]). */
    FAIL_OPEN,
}

/**
 * Expected Android application identity verified against `attestationApplicationId` (Tag 709).
 */
public data class ExpectedAndroidApp(
    val packageName: String,
    val signingCertSha256Digests: Set<ByteArray>,
) {
    init {
        require(packageName.isNotBlank()) { "packageName must not be blank" }
        require(signingCertSha256Digests.isNotEmpty()) {
            "At least one SHA-256 signing certificate digest must be configured"
        }
        for (digest in signingCertSha256Digests) {
            require(digest.size == 32) { "SHA-256 certificate digest must be 32 bytes, got ${digest.size}" }
        }
    }

    public companion object {
        /** Creates an [ExpectedAndroidApp] from colon-separated or plain hex SHA-256 cert fingerprints. */
        public fun fromHexDigests(
            packageName: String,
            vararg sha256HexDigests: String,
        ): ExpectedAndroidApp {
            val parsed =
                sha256HexDigests
                    .map { raw ->
                        val clean = raw.replace(":", "").trim().lowercase()
                        require(clean.length == 64) { "Invalid SHA-256 hex digest length: ${clean.length}" }
                        ByteArray(32) { i ->
                            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
                        }
                    }.toSet()
            return ExpectedAndroidApp(packageName = packageName, signingCertSha256Digests = parsed)
        }

        /** Creates an [ExpectedAndroidApp] from Base64url-encoded 32-byte SHA-256 digests. */
        public fun fromBase64UrlDigests(
            packageName: String,
            vararg base64UrlDigests: String,
        ): ExpectedAndroidApp {
            val parsed = base64UrlDigests.map { Base64Url.decode(it) }.toSet()
            return ExpectedAndroidApp(packageName = packageName, signingCertSha256Digests = parsed)
        }
    }
}

/**
 * Configurable security policy enforced by [MaigBindVerifier].
 */
public data class VerificationPolicy(
    val requireStrongBox: Boolean = false,
    val minOsPatchLevel: Int? = null,
    val allowFactoryKeys: Boolean = true,
    val allowWeakBiometricOptIn: Boolean = false,
    val requireUnlockedDeviceTag: Boolean = false,
    val expectedApps: List<ExpectedAndroidApp> = emptyList(),
    val failMode: FailMode = FailMode.FAIL_CLOSED,
    val clockSkewSeconds: Long = 60L,
    val keyboxSuspicionThreshold: Int = 50,
    val rejectOnSuspiciousKeybox: Boolean = false,
) {
    init {
        require(clockSkewSeconds >= 0L) { "clockSkewSeconds must be >= 0" }
        require(keyboxSuspicionThreshold > 0) { "keyboxSuspicionThreshold must be > 0" }
    }
}
