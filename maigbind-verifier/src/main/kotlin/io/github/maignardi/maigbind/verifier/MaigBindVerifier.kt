package io.github.maignardi.maigbind.verifier

import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.CanonicalValue
import io.github.maignardi.maigbind.core.EnrollmentAttestResponse
import io.github.maignardi.maigbind.core.EnrollmentConfirmRequest
import io.github.maignardi.maigbind.core.EnrollmentConfirmResponse
import io.github.maignardi.maigbind.core.EnrollmentRequest
import io.github.maignardi.maigbind.core.EnrollmentStatus
import io.github.maignardi.maigbind.core.Finding
import io.github.maignardi.maigbind.core.FindingCode
import io.github.maignardi.maigbind.core.FindingSeverity
import io.github.maignardi.maigbind.core.SecurityBacking
import io.github.maignardi.maigbind.core.SignedPayload
import io.github.maignardi.maigbind.core.VerdictStatus
import io.github.maignardi.maigbind.core.VerificationVerdict
import io.github.maignardi.maigbind.core.computeKeyId
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.time.Clock
import java.util.Date
import java.util.UUID

/** Server-issued attestation challenge returned at the start of enrollment. */
public data class EnrollmentChallengeResponse(
    val challengeBase64Url: String,
    val issuedAt: Long,
    val expiresAt: Long,
)

/** Server-issued transaction nonce returned before signing a sensitive operation. */
public data class TransactionChallengeResponse(
    val nonceBase64Url: String,
    val issuedAt: Long,
    val expiresAt: Long,
)

/**
 * Server-side verifier implementing Android hardware key attestation validation, Google CRL
 * revocation checking, immediate Proof-of-Possession enrollment confirmation, binding revocation,
 * and per-transaction ECDSA signature and payload integrity verification.
 */
public class MaigBindVerifier(
    private val policy: VerificationPolicy = VerificationPolicy(),
    trustStoreProvider: TrustStoreProvider = GoogleTrustStoreProvider(),
    revocationStatusProvider: RevocationStatusProvider = GoogleRevocationStatusProvider(),
    private val challengeStore: ChallengeStore = InMemoryChallengeStore(),
    private val nonceStore: NonceStore = InMemoryNonceStore(),
    private val bindingStore: BindingStore = InMemoryBindingStore(),
    private val keyboxUsageTracker: KeyboxUsageTracker = InMemoryKeyboxUsageTracker(),
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
) {
    private val attestationValidator =
        AttestationValidator(
            policy = policy,
            trustStoreProvider = trustStoreProvider,
            revocationStatusProvider = revocationStatusProvider,
        )

    init {
        ensureBouncyCastleRegistered()
    }

    /**
     * Step 0 of enrollment: issues a single-use 32-byte server challenge bound to [accountId].
     *
     * **Important:** Integrators MUST only call this after strong step-up authentication (MFA / eKYC)
     * to prevent enrollment hijacking.
     */
    public fun beginEnrollment(
        accountId: String,
        ttlSeconds: Long = 120L,
    ): EnrollmentChallengeResponse {
        require(accountId.isNotBlank()) { "accountId must not be blank" }
        require(ttlSeconds > 0L) { "ttlSeconds must be > 0" }
        val challenge = ByteArray(32).also { random.nextBytes(it) }
        val now = clock.millis()
        val expiresAt = now + ttlSeconds * 1_000L
        challengeStore.saveChallenge(enrollChallengeKey(accountId), challenge, expiresAt)
        return EnrollmentChallengeResponse(
            challengeBase64Url = Base64Url.encode(challenge),
            issuedAt = now,
            expiresAt = expiresAt,
        )
    }

    /**
     * Step 1 of enrollment: validates the X.509 attestation chain, revocation status,
     * `hardwareEnforced` KeyDescription fields, `attestationApplicationId` (Tag 709), and leaf
     * public key match, then stores a `PENDING_POP` binding and issues a short-lived `popChallenge`.
     */
    public fun verifyEnrollmentAttestation(request: EnrollmentRequest): EnrollmentAttestResponse {
        val findings = mutableListOf<Finding>()
        val now = clock.millis()

        val (spkiBytes, challengeBytes) =
            decodeAndCheckChallenge(request, now, findings)
                ?: return rejectAttest(request.keyId, VerdictStatus.REJECTED_FRAUD_SIGNAL, findings)

        val certificates =
            parseNonEmptyChain(request.attestationChainBase64Url, findings)
                ?: return rejectAttest(request.keyId, VerdictStatus.REJECTED_FRAUD_SIGNAL, findings)

        val pkixOutcome = attestationValidator.validatePkixChain(certificates, Date(now), findings)
        if (pkixOutcome.infraFailure) {
            return rejectAttest(request.keyId, VerdictStatus.ERROR_VALIDATION_INFRA, findings)
        }
        val matchedRoot =
            pkixOutcome.matchedRoot
                ?: return rejectAttest(request.keyId, VerdictStatus.REJECTED_FRAUD_SIGNAL, findings)

        val isRkpChain = EmbeddedGoogleRoots.isRkpRoot(matchedRoot)
        if (!isRkpChain && !policy.allowFactoryKeys) {
            findings +=
                critical(
                    FindingCode.FACTORY_KEY_NOT_ALLOWED,
                    "Policy requires RKP-provisioned attestation; factory-keyed chains are disallowed",
                )
        }

        if (!attestationValidator.checkRevocation(certificates, findings)) {
            return rejectAttest(request.keyId, VerdictStatus.ERROR_VALIDATION_INFRA, findings)
        }

        val record =
            parseLeafExtension(certificates.first(), findings)
                ?: return rejectAttest(request.keyId, VerdictStatus.REJECTED_FRAUD_SIGNAL, findings)

        attestationValidator.validateAttestationRecord(
            record = record,
            expectedChallenge = challengeBytes,
            leafCert = certificates.first(),
            expectedSpkiBytes = spkiBytes,
            findings = findings,
        )

        val batchKey = attestationValidator.computeBatchKey(certificates, matchedRoot)
        checkKeyboxFanOut(isRkpChain, batchKey, request.accountId, now, findings)

        if (findings.any { it.severity == FindingSeverity.CRITICAL }) {
            return rejectAttest(request.keyId, classifyRejection(findings), findings)
        }

        return persistPendingBindingAndIssuePop(request, record, isRkpChain, batchKey, now, findings)
    }

    /**
     * Step 2 of enrollment: verifies the immediate biometric-unlocked Proof-of-Possession signature
     * using the enrolled public key, enforces [VerificationPolicy.maxActiveBindingsPerAccount]
     * (revoking oldest superseded active bindings), and activates the binding.
     */
    public fun confirmEnrollmentPop(request: EnrollmentConfirmRequest): EnrollmentConfirmResponse {
        val findings = mutableListOf<Finding>()
        val now = clock.millis()
        val binding = bindingStore.findByBindingId(request.bindingId)
        if (binding == null || binding.status != EnrollmentStatus.PENDING_POP) {
            findings +=
                critical(
                    FindingCode.BINDING_NOT_FOUND_OR_INACTIVE,
                    "Binding '${request.bindingId}' not found or not in PENDING_POP state",
                )
            return EnrollmentConfirmResponse(
                bindingId = request.bindingId,
                keyId = request.popPayload.keyId,
                status = binding?.status ?: EnrollmentStatus.REVOKED,
                verdict =
                    VerificationVerdict(
                        status = VerdictStatus.REJECTED_FRAUD_SIGNAL,
                        keyId = request.popPayload.keyId,
                        findings = findings,
                    ),
            )
        }

        val precheckFailure = checkPopPreconditions(request, binding, now, findings)
        if (precheckFailure != null) {
            return rejectPop(binding, precheckFailure, findings)
        }

        val sigValid =
            verifyEcdsaSignature(
                spkiBase64Url = binding.publicKeySpkiBase64Url,
                signingInput = request.popPayload.signingInput(),
                signatureBase64Url = request.signatureBase64Url,
            )
        if (!sigValid) {
            findings +=
                critical(
                    FindingCode.SIGNATURE_INVALID,
                    "ECDSA Proof-of-Possession signature verification failed",
                )
            return rejectPop(binding, VerdictStatus.REJECTED_FRAUD_SIGNAL, findings)
        }

        enforceMaxActiveBindings(binding.accountId, binding.bindingId, now)
        val activated = binding.copy(status = EnrollmentStatus.ACTIVE, activatedAtMillis = now)
        bindingStore.save(activated)

        return EnrollmentConfirmResponse(
            bindingId = activated.bindingId,
            keyId = activated.keyId,
            status = EnrollmentStatus.ACTIVE,
            verdict =
                VerificationVerdict(
                    status = VerdictStatus.VERIFIED,
                    keyId = activated.keyId,
                    securityBacking = activated.securityBacking,
                    isRkpChain = activated.isRkpChain,
                    findings = listOf(Finding(FindingCode.OK, FindingSeverity.INFO, "Device binding activated")),
                ),
        )
    }

    /**
     * Revokes a specific device [bindingId] (e.g., stolen phone or "remove this device" action).
     *
     * @return `true` if the binding existed and transitioned to [EnrollmentStatus.REVOKED].
     */
    public fun revokeBinding(bindingId: String): Boolean {
        require(bindingId.isNotBlank()) { "bindingId must not be blank" }
        return bindingStore.revoke(bindingId, clock.millis())
    }

    /**
     * Revokes all non-revoked device bindings for [accountId] (e.g., account takeover response).
     *
     * @return the number of bindings revoked.
     */
    public fun revokeAccountBindings(accountId: String): Int {
        require(accountId.isNotBlank()) { "accountId must not be blank" }
        return bindingStore.revokeAllForAccount(accountId, clock.millis())
    }

    /** Returns all currently [EnrollmentStatus.ACTIVE] bindings for [accountId]. */
    public fun getActiveBindings(accountId: String): List<DeviceBinding> {
        require(accountId.isNotBlank()) { "accountId must not be blank" }
        return bindingStore.findActiveByAccount(accountId)
    }

    /**
     * Issues a single-use transaction nonce bound to an active [keyId] for [accountId].
     */
    public fun issueTransactionNonce(
        accountId: String,
        keyId: String,
        ttlSeconds: Long = 90L,
    ): TransactionChallengeResponse {
        require(accountId.isNotBlank()) { "accountId must not be blank" }
        require(keyId.isNotBlank()) { "keyId must not be blank" }
        require(ttlSeconds > 0L) { "ttlSeconds must be > 0" }

        val binding =
            bindingStore.findByAccountAndKeyId(accountId, keyId)
                ?: throw IllegalStateException("No device binding found for account '$accountId' and key '$keyId'")
        require(binding.status == EnrollmentStatus.ACTIVE) {
            "Device binding '$keyId' is not ACTIVE (status=${binding.status})"
        }

        val nonceBytes = ByteArray(32).also { random.nextBytes(it) }
        val nonceStr = Base64Url.encode(nonceBytes)
        val now = clock.millis()
        val expiresAt = now + ttlSeconds * 1_000L
        nonceStore.issueNonce(keyId, nonceStr, expiresAt)
        return TransactionChallengeResponse(
            nonceBase64Url = nonceStr,
            issuedAt = now,
            expiresAt = expiresAt,
        )
    }

    /**
     * Verifies a signed sensitive operation against the enrolled `ACTIVE` binding, single-use nonce,
     * expiration window, `"MaigBind/v1/tx\0"` domain tag, ECDSA P-256 signature, and exact
     * field-by-field parity with the command the server is about to execute.
     */
    public fun verifyTransaction(
        accountId: String,
        signedPayload: SignedPayload,
        expectedOperationType: String,
        expectedFields: Map<String, CanonicalValue>,
    ): VerificationVerdict {
        val payload = signedPayload.payload
        val findings = mutableListOf<Finding>()
        val now = clock.millis()

        val binding = bindingStore.findByAccountAndKeyId(accountId, payload.keyId)
        if (binding == null || binding.status != EnrollmentStatus.ACTIVE) {
            findings +=
                critical(
                    FindingCode.BINDING_NOT_FOUND_OR_INACTIVE,
                    "No ACTIVE binding found for account '$accountId' and keyId '${payload.keyId}'",
                )
            return VerificationVerdict(VerdictStatus.REJECTED_FRAUD_SIGNAL, payload.keyId, findings = findings)
        }

        if (policy.requireStrongBox && binding.securityBacking != SecurityBacking.STRONGBOX) {
            findings +=
                critical(
                    FindingCode.STRONGBOX_REQUIRED,
                    "Policy requires StrongBox backing, found ${binding.securityBacking}",
                )
            return bindingVerdict(binding, VerdictStatus.REJECTED_POLICY, findings)
        }

        val cryptoFailure = checkTransactionFreshnessAndSignature(binding, signedPayload, now, findings)
        if (cryptoFailure != null) {
            return bindingVerdict(binding, cryptoFailure, findings)
        }

        if (payload.operationType != expectedOperationType) {
            findings +=
                critical(
                    FindingCode.PAYLOAD_FIELD_MISMATCH,
                    "Signed operationType '${payload.operationType}' != expected '$expectedOperationType'",
                )
        }
        if (!fieldsEqual(payload.fields, expectedFields)) {
            findings +=
                critical(
                    FindingCode.PAYLOAD_FIELD_MISMATCH,
                    "Signed transaction fields do not match executed command fields",
                )
        }
        if (findings.isNotEmpty()) {
            return bindingVerdict(binding, VerdictStatus.REJECTED_FRAUD_SIGNAL, findings)
        }

        return bindingVerdict(
            binding,
            VerdictStatus.VERIFIED,
            listOf(Finding(FindingCode.OK, FindingSeverity.INFO, "Transaction signature and payload verified")),
        )
    }

    private fun enforceMaxActiveBindings(
        accountId: String,
        newBindingId: String,
        nowMillis: Long,
    ) {
        val existingActive =
            bindingStore
                .findActiveByAccount(accountId)
                .filter { it.bindingId != newBindingId }
                .sortedBy { it.activatedAtMillis ?: it.createdAtMillis }
        val allowedPrior = policy.maxActiveBindingsPerAccount - 1
        val excess = existingActive.size - allowedPrior
        if (excess > 0) {
            for (oldBinding in existingActive.take(excess)) {
                bindingStore.revoke(oldBinding.bindingId, nowMillis)
            }
        }
    }

    private fun decodeAndCheckChallenge(
        request: EnrollmentRequest,
        now: Long,
        findings: MutableList<Finding>,
    ): Pair<ByteArray, ByteArray>? {
        val spkiBytes = runCatching { Base64Url.decode(request.publicKeySpkiBase64Url) }.getOrNull()
        val challengeBytes = runCatching { Base64Url.decode(request.challengeBase64Url) }.getOrNull()
        if (spkiBytes == null || challengeBytes == null) {
            findings +=
                critical(
                    FindingCode.CHALLENGE_INVALID_OR_EXPIRED,
                    "Malformed base64url in enrollment request",
                )
            return null
        }
        if (computeKeyId(spkiBytes) != request.keyId) {
            findings +=
                critical(
                    FindingCode.KEY_ID_MISMATCH,
                    "Submitted keyId does not match SHA-256(publicKeySpki)",
                )
            return null
        }
        if (!challengeStore.consumeChallenge(enrollChallengeKey(request.accountId), challengeBytes, now)) {
            findings +=
                critical(
                    FindingCode.CHALLENGE_INVALID_OR_EXPIRED,
                    "Attestation challenge is unknown, expired, or already consumed",
                )
            return null
        }
        return spkiBytes to challengeBytes
    }

    private fun parseNonEmptyChain(
        chainBase64Url: List<String>,
        findings: MutableList<Finding>,
    ): List<X509Certificate>? {
        if (chainBase64Url.isEmpty()) {
            findings += critical(FindingCode.CERT_CHAIN_EMPTY, "Attestation certificate chain is empty")
            return null
        }
        val parsed = attestationValidator.parseCertificates(chainBase64Url)
        if (parsed == null) {
            findings +=
                critical(
                    FindingCode.CERT_CHAIN_INVALID_SIGNATURE,
                    "Unable to parse X.509 certificate(s) in attestation chain",
                )
        }
        return parsed
    }

    private fun parseLeafExtension(
        leaf: X509Certificate,
        findings: MutableList<Finding>,
    ): AttestationRecord? =
        try {
            KeyAttestationParser.parseOrNull(leaf).also { parsed ->
                if (parsed == null) {
                    findings +=
                        critical(
                            FindingCode.ATTESTATION_EXTENSION_MISSING,
                            "Leaf certificate does not contain Android Key Attestation extension",
                        )
                }
            }
        } catch (ex: IllegalArgumentException) {
            findings +=
                critical(
                    FindingCode.ATTESTATION_EXTENSION_MALFORMED,
                    "Malformed KeyDescription extension: ${ex.message}",
                )
            null
        }

    private fun checkKeyboxFanOut(
        isRkpChain: Boolean,
        batchKey: String?,
        accountId: String,
        nowMillis: Long,
        findings: MutableList<Finding>,
    ) {
        if (isRkpChain || batchKey == null) return
        val windowMillis = policy.keyboxSuspicionWindowMinutes * 60_000L
        val distinctAccounts =
            keyboxUsageTracker.recordAndCountInWindow(batchKey, accountId, nowMillis, windowMillis)
        if (distinctAccounts >= policy.keyboxSuspicionThreshold) {
            val sev = if (policy.rejectOnSuspiciousKeybox) FindingSeverity.CRITICAL else FindingSeverity.WARNING
            findings +=
                Finding(
                    code = FindingCode.SUSPICIOUS_KEYBOX_FANOUT,
                    severity = sev,
                    message =
                        "Batch attestation CA attested $distinctAccounts distinct accounts " +
                            "within ${policy.keyboxSuspicionWindowMinutes}m",
                    details = mapOf("batchKey" to batchKey, "distinctAccounts" to distinctAccounts.toString()),
                )
        }
    }

    private fun persistPendingBindingAndIssuePop(
        request: EnrollmentRequest,
        record: AttestationRecord,
        isRkpChain: Boolean,
        batchKey: String?,
        now: Long,
        findings: MutableList<Finding>,
    ): EnrollmentAttestResponse {
        val resolvedBacking =
            when (record.keymasterSecurityLevel) {
                AttestationSecurityLevel.STRONG_BOX -> SecurityBacking.STRONGBOX
                AttestationSecurityLevel.TRUSTED_ENVIRONMENT -> SecurityBacking.TEE
                AttestationSecurityLevel.SOFTWARE -> SecurityBacking.UNKNOWN
            }
        val bindingId = UUID.randomUUID().toString()
        bindingStore.save(
            DeviceBinding(
                bindingId = bindingId,
                accountId = request.accountId,
                keyId = request.keyId,
                publicKeySpkiBase64Url = request.publicKeySpkiBase64Url,
                status = EnrollmentStatus.PENDING_POP,
                securityBacking = resolvedBacking,
                isRkpChain = isRkpChain,
                issuerBatchKey = batchKey,
                createdAtMillis = now,
            ),
        )
        val popChallenge = ByteArray(32).also { random.nextBytes(it) }
        val popExpiresAt = now + 60_000L
        challengeStore.saveChallenge(popChallengeKey(bindingId), popChallenge, popExpiresAt)

        findings +=
            Finding(
                code = FindingCode.OK,
                severity = FindingSeverity.INFO,
                message = "Attestation verified; awaiting biometric Proof-of-Possession",
            )
        return EnrollmentAttestResponse(
            bindingId = bindingId,
            keyId = request.keyId,
            status = EnrollmentStatus.PENDING_POP,
            popChallengeBase64Url = Base64Url.encode(popChallenge),
            popExpiresAt = popExpiresAt,
            verdict =
                VerificationVerdict(
                    status = VerdictStatus.VERIFIED,
                    keyId = request.keyId,
                    securityBacking = resolvedBacking,
                    isRkpChain = isRkpChain,
                    findings = findings,
                ),
        )
    }

    private fun checkPopPreconditions(
        request: EnrollmentConfirmRequest,
        binding: DeviceBinding,
        now: Long,
        findings: MutableList<Finding>,
    ): VerdictStatus? {
        if (request.popPayload.keyId != binding.keyId || request.popPayload.accountId != binding.accountId) {
            findings += critical(FindingCode.KEY_ID_MISMATCH, "PoP payload keyId/accountId mismatch")
            return VerdictStatus.REJECTED_FRAUD_SIGNAL
        }
        val challengeBytes = runCatching { Base64Url.decode(request.popPayload.challenge) }.getOrNull()
        if (challengeBytes == null ||
            !challengeStore.consumeChallenge(popChallengeKey(binding.bindingId), challengeBytes, now)
        ) {
            findings +=
                critical(
                    FindingCode.POP_CHALLENGE_INVALID_OR_EXPIRED,
                    "PoP challenge is unknown, expired, or already consumed",
                )
            return VerdictStatus.REJECTED_FRAUD_SIGNAL
        }
        val skewMs = policy.clockSkewSeconds * 1_000L
        if (now > request.popPayload.expiresAt + skewMs || request.popPayload.issuedAt > now + skewMs) {
            findings +=
                critical(
                    FindingCode.PAYLOAD_EXPIRED_OR_FUTURE,
                    "PoP payload timestamps outside allowed validity window",
                )
            return VerdictStatus.REJECTED_FRAUD_SIGNAL
        }
        return null
    }

    private fun checkTransactionFreshnessAndSignature(
        binding: DeviceBinding,
        signedPayload: SignedPayload,
        now: Long,
        findings: MutableList<Finding>,
    ): VerdictStatus? {
        val payload = signedPayload.payload
        if (!nonceStore.consumeIfUnused(binding.keyId, payload.nonce, now)) {
            findings +=
                critical(
                    FindingCode.NONCE_REPLAYED_OR_UNKNOWN,
                    "Transaction nonce is unknown, expired, or already consumed (possible replay)",
                )
            return VerdictStatus.REJECTED_FRAUD_SIGNAL
        }
        val skewMs = policy.clockSkewSeconds * 1_000L
        if (now > payload.expiresAt + skewMs || payload.issuedAt > now + skewMs) {
            findings +=
                critical(
                    FindingCode.PAYLOAD_EXPIRED_OR_FUTURE,
                    "Transaction payload expired or issued in the future",
                )
            return VerdictStatus.REJECTED_FRAUD_SIGNAL
        }
        if (!verifyEcdsaSignature(
                spkiBase64Url = binding.publicKeySpkiBase64Url,
                signingInput = payload.signingInput(),
                signatureBase64Url = signedPayload.signatureBase64Url,
            )
        ) {
            findings += critical(FindingCode.SIGNATURE_INVALID, "ECDSA transaction signature verification failed")
            return VerdictStatus.REJECTED_FRAUD_SIGNAL
        }
        return null
    }

    private fun verifyEcdsaSignature(
        spkiBase64Url: String,
        signingInput: ByteArray,
        signatureBase64Url: String,
    ): Boolean =
        runCatching {
            val spkiBytes = Base64Url.decode(spkiBase64Url)
            val sigBytes = Base64Url.decode(signatureBase64Url)
            val pubKey: PublicKey =
                KeyFactory
                    .getInstance("EC")
                    .generatePublic(X509EncodedKeySpec(spkiBytes))
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(pubKey)
                update(signingInput)
                verify(sigBytes)
            }
        }.getOrDefault(false)

    private fun fieldsEqual(
        actual: Map<String, CanonicalValue>,
        expected: Map<String, CanonicalValue>,
    ): Boolean {
        if (actual.size != expected.size) return false
        return expected.all { (k, expectedVal) ->
            actual[k]?.let { expectedVal.contentEquals(it) } == true
        }
    }

    private fun classifyRejection(findings: List<Finding>): VerdictStatus {
        val policyOnlyCodes =
            setOf(
                FindingCode.STRONGBOX_REQUIRED,
                FindingCode.OS_PATCH_LEVEL_TOO_LOW,
                FindingCode.FACTORY_KEY_NOT_ALLOWED,
            )
        val criticalCodes =
            findings
                .filter { it.severity == FindingSeverity.CRITICAL }
                .map { it.code }
                .toSet()
        return if (criticalCodes.isNotEmpty() && criticalCodes.all { it in policyOnlyCodes }) {
            VerdictStatus.REJECTED_POLICY
        } else {
            VerdictStatus.REJECTED_FRAUD_SIGNAL
        }
    }

    private fun bindingVerdict(
        binding: DeviceBinding,
        status: VerdictStatus,
        findings: List<Finding>,
    ): VerificationVerdict =
        VerificationVerdict(
            status = status,
            keyId = binding.keyId,
            securityBacking = binding.securityBacking,
            isRkpChain = binding.isRkpChain,
            findings = findings,
        )

    private fun rejectAttest(
        keyId: String,
        status: VerdictStatus,
        findings: List<Finding>,
    ): EnrollmentAttestResponse =
        EnrollmentAttestResponse(
            bindingId = "",
            keyId = keyId,
            status = EnrollmentStatus.REVOKED,
            popChallengeBase64Url = "",
            popExpiresAt = 0L,
            verdict = VerificationVerdict(status = status, keyId = keyId, findings = findings),
        )

    private fun rejectPop(
        binding: DeviceBinding,
        status: VerdictStatus,
        findings: List<Finding>,
    ): EnrollmentConfirmResponse =
        EnrollmentConfirmResponse(
            bindingId = binding.bindingId,
            keyId = binding.keyId,
            status = binding.status,
            verdict = bindingVerdict(binding, status, findings),
        )

    private fun critical(
        code: FindingCode,
        message: String,
        details: Map<String, String> = emptyMap(),
    ): Finding = Finding(code = code, severity = FindingSeverity.CRITICAL, message = message, details = details)

    private fun enrollChallengeKey(accountId: String): String = "enroll::$accountId"

    private fun popChallengeKey(bindingId: String): String = "pop::$bindingId"

    private companion object {
        fun ensureBouncyCastleRegistered() {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }
    }
}
