package io.github.maignardi.maigbind.verifier

import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.Finding
import io.github.maignardi.maigbind.core.FindingCode
import io.github.maignardi.maigbind.core.FindingSeverity
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertPathValidator
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date

internal data class PkixOutcome(
    val matchedRoot: X509Certificate? = null,
    val infraFailure: Boolean = false,
)

/**
 * Internal helper encapsulating X.509 PKIX path verification, Google CRL checking, and
 * AOSP `KeyDescription` (`OID 1.3.6.1.4.1.11129.2.1.17`) policy validation.
 */
internal class AttestationValidator(
    private val policy: VerificationPolicy,
    private val trustStoreProvider: TrustStoreProvider,
    private val revocationStatusProvider: RevocationStatusProvider,
) {
    fun parseCertificates(chainBase64Url: List<String>): List<X509Certificate>? =
        runCatching {
            val cf = CertificateFactory.getInstance("X.509")
            chainBase64Url.map { b64 ->
                cf.generateCertificate(ByteArrayInputStream(Base64Url.decode(b64))) as X509Certificate
            }
        }.getOrNull()

    fun validatePkixChain(
        certificates: List<X509Certificate>,
        validationDate: Date,
        findings: MutableList<Finding>,
    ): PkixOutcome {
        val snapshot = trustStoreProvider.getTrustedRoots()
        if (snapshot.roots.isEmpty() && policy.failMode == FailMode.FAIL_CLOSED) {
            findings +=
                critical(
                    FindingCode.INFRA_TRUST_STORE_UNAVAILABLE,
                    "Trust store unavailable: ${snapshot.failureReason}",
                )
            return PkixOutcome(infraFailure = true)
        }

        if (!checkCertificateDates(certificates, validationDate, findings)) {
            return PkixOutcome()
        }

        val trustAnchors = snapshot.roots.map { TrustAnchor(it, null) }.toSet()
        val cf = CertificateFactory.getInstance("X.509")
        val rootSet = snapshot.roots.map { it.encoded.toList() }.toSet()
        val pathCerts =
            if (certificates.size > 1 && certificates.last().encoded.toList() in rootSet) {
                certificates.dropLast(1)
            } else {
                certificates
            }

        return try {
            val certPath = cf.generateCertPath(pathCerts)
            val params =
                PKIXParameters(trustAnchors).apply {
                    isRevocationEnabled = false
                    date = validationDate
                }
            val result =
                CertPathValidator.getInstance("PKIX").validate(certPath, params)
                    as PKIXCertPathValidatorResult
            PkixOutcome(matchedRoot = result.trustAnchor.trustedCert)
        } catch (ex: Exception) {
            val msg = ex.message.orEmpty()
            val code =
                if (msg.contains("trust anchor", ignoreCase = true) ||
                    msg.contains("Path does not chain", ignoreCase = true)
                ) {
                    FindingCode.CERT_CHAIN_UNTRUSTED_ROOT
                } else {
                    FindingCode.CERT_CHAIN_INVALID_SIGNATURE
                }
            findings += critical(code, "PKIX chain validation failed: $msg")
            PkixOutcome()
        }
    }

    fun checkRevocation(
        certificates: List<X509Certificate>,
        findings: MutableList<Finding>,
    ): Boolean =
        when (val revStatus = revocationStatusProvider.checkChain(certificates)) {
            is RevocationCheckResult.Clear -> true
            is RevocationCheckResult.Revoked -> {
                findings +=
                    critical(
                        FindingCode.CERT_REVOKED_OR_SUSPENDED,
                        "Certificate serial ${revStatus.serialKey} is ${revStatus.status}",
                        mapOf("reason" to (revStatus.reason ?: "UNSPECIFIED")),
                    )
                true
            }
            is RevocationCheckResult.Unavailable -> {
                if (policy.failMode == FailMode.FAIL_CLOSED) {
                    findings +=
                        critical(
                            FindingCode.INFRA_REVOCATION_LIST_UNAVAILABLE,
                            "Revocation list unavailable in FAIL_CLOSED mode: ${revStatus.error}",
                        )
                    false
                } else {
                    findings +=
                        Finding(
                            code = FindingCode.INFRA_FAIL_OPEN_APPLIED,
                            severity = FindingSeverity.WARNING,
                            message = "Revocation list unavailable; FAIL_OPEN policy applied: ${revStatus.error}",
                        )
                    true
                }
            }
        }

    fun validateAttestationRecord(
        record: AttestationRecord,
        expectedChallenge: ByteArray,
        leafCert: X509Certificate,
        expectedSpkiBytes: ByteArray,
        findings: MutableList<Finding>,
    ) {
        validateTopLevelRecord(record, expectedChallenge, findings)
        val bootVerified = validateHardwareEnforcedTags(record.hardwareEnforced, findings)
        validateApplicationBinding(record.softwareEnforced, bootVerified, findings)
        if (!MessageDigest.isEqual(leafCert.publicKey.encoded, expectedSpkiBytes)) {
            findings +=
                critical(
                    FindingCode.LEAF_PUBLIC_KEY_MISMATCH,
                    "Attestation leaf certificate public key does not match submitted publicKeySpki",
                )
        }
    }

    private fun validateTopLevelRecord(
        record: AttestationRecord,
        expectedChallenge: ByteArray,
        findings: MutableList<Finding>,
    ) {
        if (!MessageDigest.isEqual(record.attestationChallenge, expectedChallenge)) {
            findings +=
                critical(
                    FindingCode.ATTESTATION_CHALLENGE_MISMATCH,
                    "Attestation extension challenge does not match issued server challenge",
                )
        }
        if (record.attestationSecurityLevel == AttestationSecurityLevel.SOFTWARE) {
            findings +=
                critical(
                    FindingCode.ATTESTATION_SECURITY_LEVEL_TOO_LOW,
                    "attestationSecurityLevel is SOFTWARE; hardware backing required",
                )
        }
        if (record.keymasterSecurityLevel == AttestationSecurityLevel.SOFTWARE) {
            findings +=
                critical(
                    FindingCode.KEYMASTER_SECURITY_LEVEL_TOO_LOW,
                    "keymasterSecurityLevel is SOFTWARE; hardware backing required",
                )
        }
        if (policy.requireStrongBox &&
            record.keymasterSecurityLevel != AttestationSecurityLevel.STRONG_BOX
        ) {
            findings +=
                critical(
                    FindingCode.STRONGBOX_REQUIRED,
                    "Policy requires STRONG_BOX keymasterSecurityLevel, found ${record.keymasterSecurityLevel}",
                )
        }
    }

    private fun validateHardwareEnforcedTags(
        hw: AuthorizationList,
        findings: MutableList<Finding>,
    ): Boolean {
        val rot = hw.rootOfTrust
        val bootVerified =
            rot != null &&
                rot.deviceLocked &&
                rot.verifiedBootState == VerifiedBootState.VERIFIED
        if (!bootVerified) {
            findings +=
                critical(
                    FindingCode.BOOTLOADER_UNLOCKED_OR_UNVERIFIED,
                    "hardwareEnforced rootOfTrust failed: deviceLocked=${rot?.deviceLocked}, " +
                        "verifiedBootState=${rot?.verifiedBootState}",
                )
        }
        validateKeyProperties(hw, findings)
        validateBiometricAuthProperties(hw, findings)
        val minPatch = policy.minOsPatchLevel
        if (minPatch != null && (hw.osPatchLevel == null || hw.osPatchLevel < minPatch)) {
            findings +=
                critical(
                    FindingCode.OS_PATCH_LEVEL_TOO_LOW,
                    "hardwareEnforced osPatchLevel (${hw.osPatchLevel}) < policy minimum $minPatch",
                )
        }
        return bootVerified
    }

    private fun validateKeyProperties(
        hw: AuthorizationList,
        findings: MutableList<Finding>,
    ) {
        if (KeyAttestationParser.KM_PURPOSE_SIGN !in hw.purposes) {
            findings +=
                critical(
                    FindingCode.KEY_PURPOSE_INVALID,
                    "hardwareEnforced purpose does not include SIGN (found ${hw.purposes})",
                )
        }
        if (hw.algorithm != KeyAttestationParser.KM_ALGORITHM_EC ||
            hw.ecCurve != KeyAttestationParser.KM_EC_CURVE_P_256
        ) {
            findings +=
                critical(
                    FindingCode.KEY_ALGORITHM_OR_CURVE_INVALID,
                    "Expected EC P-256 in hardwareEnforced, found alg=${hw.algorithm}, curve=${hw.ecCurve}",
                )
        }
    }

    private fun validateBiometricAuthProperties(
        hw: AuthorizationList,
        findings: MutableList<Finding>,
    ) {
        if (hw.noAuthRequired) {
            findings +=
                critical(
                    FindingCode.KEY_NO_AUTH_REQUIRED_PRESENT,
                    "hardwareEnforced contains noAuthRequired",
                )
        }
        val authType = hw.userAuthType
        if (authType == null || (authType and KeyAttestationParser.HW_AUTH_BIOMETRIC) == 0L) {
            findings +=
                critical(
                    FindingCode.KEY_AUTH_TYPE_NOT_BIOMETRIC,
                    "hardwareEnforced userAuthType ($authType) does not enforce biometric auth",
                )
        }
        if (hw.authTimeoutSeconds != null && hw.authTimeoutSeconds > 0L) {
            findings +=
                critical(
                    FindingCode.KEY_AUTH_TIMEOUT_NOT_PER_USE,
                    "hardwareEnforced authTimeout (${hw.authTimeoutSeconds}s) must be absent or 0",
                )
        }
    }

    private fun validateApplicationBinding(
        sw: AuthorizationList,
        bootVerified: Boolean,
        findings: MutableList<Finding>,
    ) {
        if (policy.expectedApps.isEmpty()) return
        val appId = sw.attestationApplicationId
        val matched = bootVerified && appId != null && matchesExpectedApp(appId, policy.expectedApps)
        if (!matched) {
            findings +=
                critical(
                    FindingCode.APP_IDENTITY_MISMATCH,
                    "attestationApplicationId (Tag 709) did not match any configured expected app",
                )
        }
    }

    private fun matchesExpectedApp(
        appId: AttestationApplicationId,
        expectedApps: List<ExpectedAndroidApp>,
    ): Boolean =
        expectedApps.any { expected ->
            val pkgMatches = appId.packages.any { it.packageName == expected.packageName }
            val sigMatches =
                appId.signatureDigests.any { actualDigest ->
                    expected.signingCertSha256Digests.any { expectedDigest ->
                        MessageDigest.isEqual(actualDigest, expectedDigest)
                    }
                }
            pkgMatches && sigMatches
        }

    private fun checkCertificateDates(
        certificates: List<X509Certificate>,
        validationDate: Date,
        findings: MutableList<Finding>,
    ): Boolean {
        for ((idx, cert) in certificates.withIndex()) {
            try {
                cert.checkValidity(validationDate)
            } catch (ex: CertificateExpiredException) {
                findings +=
                    critical(
                        FindingCode.CERT_CHAIN_EXPIRED_OR_NOT_YET_VALID,
                        "Certificate [$idx] expired: ${ex.message}",
                    )
                return false
            } catch (ex: CertificateNotYetValidException) {
                findings +=
                    critical(
                        FindingCode.CERT_CHAIN_EXPIRED_OR_NOT_YET_VALID,
                        "Certificate [$idx] not yet valid: ${ex.message}",
                    )
                return false
            }
        }
        return true
    }

    fun computeBatchKey(
        certificates: List<X509Certificate>,
        matchedRoot: X509Certificate,
    ): String? {
        val intermediate =
            certificates.lastOrNull {
                !it.encoded.contentEquals(matchedRoot.encoded) && it != certificates.first()
            } ?: return null
        return "${intermediate.issuerX500Principal.name}#${intermediate.serialNumber.toString(16)}"
    }

    private fun critical(
        code: FindingCode,
        message: String,
        details: Map<String, String> = emptyMap(),
    ): Finding = Finding(code = code, severity = FindingSeverity.CRITICAL, message = message, details = details)
}
