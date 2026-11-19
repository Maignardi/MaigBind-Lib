package io.github.maignardi.maigbind.verifier

import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.EnrollmentConfirmRequest
import io.github.maignardi.maigbind.core.EnrollmentPoPPayload
import io.github.maignardi.maigbind.core.EnrollmentRequest
import io.github.maignardi.maigbind.core.EnrollmentStatus
import io.github.maignardi.maigbind.core.FindingCode
import io.github.maignardi.maigbind.core.SecurityBacking
import io.github.maignardi.maigbind.core.Sha256
import io.github.maignardi.maigbind.core.SignedPayload
import io.github.maignardi.maigbind.core.TransactionPayload
import io.github.maignardi.maigbind.core.VerdictStatus
import io.github.maignardi.maigbind.core.canonical
import io.github.maignardi.maigbind.core.canonicalFields
import io.github.maignardi.maigbind.core.computeKeyId
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.Security
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * Automated Attack Suite validating MaigBind server defenses against the modeled threat vectors.
 */
class AttackSuiteTest {
    private val fixedNow = Instant.parse("2026-11-18T12:00:00Z")
    private val fixedClock = Clock.fixed(fixedNow, ZoneOffset.UTC)
    private val officialApp =
        ExpectedAndroidApp(
            packageName = "io.github.maignardi.maigbind.sample.app",
            signingCertSha256Digests = setOf(Sha256.digest("official-app-key".encodeToByteArray())),
        )

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Test
    fun blocksOneShotOracleRelayViaTag709AndPendingPopGate() {
        val root = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = true)
        val verifier =
            MaigBindVerifier(
                policy = VerificationPolicy(expectedApps = listOf(officialApp)),
                trustStoreProvider = StaticTrustStoreProvider(listOf(root.cert)),
                revocationStatusProvider = StaticRevocationStatusProvider(),
                clock = fixedClock,
            )

        // Scenario A: Attacker relays challenge to a third-party oracle app on a clean device
        val (_, oracleResp) =
            attestWithIssuer(
                verifier = verifier,
                accountId = "victim-acct",
                issuer = root,
                issuerSigAlg = "SHA384withECDSA",
                serial = BigInteger.TEN,
                appPkg = "com.quarkslab.attestation.oracle",
                appDigest = Sha256.digest("oracle-signer".encodeToByteArray()),
            )
        assertFalse(oracleResp.verdict.isVerified)
        assertTrue(oracleResp.verdict.findings.any { it.code == FindingCode.APP_IDENTITY_MISMATCH })

        // Scenario B: Attacker uses genuine app on clean device for Step 1, tries to skip Step-2 PoP
        val (cleanKeyId, attestOk) =
            attestWithIssuer(
                verifier = verifier,
                accountId = "victim-acct",
                issuer = root,
                issuerSigAlg = "SHA384withECDSA",
                serial = BigInteger.valueOf(11L),
                appPkg = officialApp.packageName,
                appDigest = officialApp.signingCertSha256Digests.first(),
            )
        assertEquals(EnrollmentStatus.PENDING_POP, attestOk.status)

        val rogueKey = TestPkiFixture.generateP256KeyPair()
        val popPayload =
            EnrollmentPoPPayload(
                keyId = cleanKeyId,
                accountId = "victim-acct",
                challenge = attestOk.popChallengeBase64Url,
                issuedAt = fixedNow.toEpochMilli(),
                expiresAt = attestOk.popExpiresAt,
            )
        val forgedPop = TestPkiFixture.ecdsaSign(rogueKey.private, popPayload.signingInput())
        val confirmResp =
            verifier.confirmEnrollmentPop(
                EnrollmentConfirmRequest(
                    bindingId = attestOk.bindingId,
                    popPayload = popPayload,
                    signatureBase64Url = Base64Url.encode(forgedPop),
                ),
            )
        assertEquals(VerdictStatus.REJECTED_FRAUD_SIGNAL, confirmResp.verdict.status)
        assertEquals(EnrollmentStatus.PENDING_POP, confirmResp.status)
        assertTrue(confirmResp.verdict.findings.any { it.code == FindingCode.SIGNATURE_INVALID })
    }

    @Test
    fun forgedSoftwareKeySignatureAndRevokedBindingsAreRejectedByServer() {
        val root = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = true)
        val verifier =
            MaigBindVerifier(
                policy = VerificationPolicy(maxActiveBindingsPerAccount = 1),
                trustStoreProvider = StaticTrustStoreProvider(listOf(root.cert)),
                revocationStatusProvider = StaticRevocationStatusProvider(),
                clock = fixedClock,
            )
        val (firstKey, firstKeyId, firstBindingId) = enroll(verifier, root, "acct-attack")
        val nonce = verifier.issueTransactionNonce("acct-attack", firstKeyId)
        val payload =
            TransactionPayload(
                keyId = firstKeyId,
                operationType = "PIX_TRANSFER",
                nonce = nonce.nonceBase64Url,
                issuedAt = nonce.issuedAt,
                expiresAt = nonce.expiresAt,
                fields = canonicalFields("amountCents" to canonical(50_000L)),
            )

        // T1: Forged software key from Frida CryptoObject swap is rejected by ECDSA verification
        val rogueKey = TestPkiFixture.generateP256KeyPair()
        val forgedVerdict =
            verifier.verifyTransaction(
                accountId = "acct-attack",
                signedPayload =
                    SignedPayload(
                        payload = payload,
                        signatureBase64Url =
                            Base64Url.encode(
                                TestPkiFixture.ecdsaSign(rogueKey.private, payload.signingInput()),
                            ),
                    ),
                expectedOperationType = "PIX_TRANSFER",
                expectedFields = payload.fields,
            )
        assertEquals(VerdictStatus.REJECTED_FRAUD_SIGNAL, forgedVerdict.status)
        assertTrue(forgedVerdict.findings.any { it.code == FindingCode.SIGNATURE_INVALID })

        // Re-enrollment under maxActiveBindingsPerAccount=1 automatically revokes the prior device
        val (_, secondKeyId, secondBindingId) = enroll(verifier, root, "acct-attack")
        assertEquals(1, verifier.getActiveBindings("acct-attack").size)
        assertEquals(secondBindingId, verifier.getActiveBindings("acct-attack").single().bindingId)

        // Old stolen/superseded key can no longer obtain nonces or execute transactions
        val staleSigned =
            SignedPayload(
                payload = payload.copy(nonce = "any"),
                signatureBase64Url =
                    Base64Url.encode(
                        TestPkiFixture.ecdsaSign(firstKey.private, payload.copy(nonce = "any").signingInput()),
                    ),
            )
        val staleVerdict = verifier.verifyTransaction("acct-attack", staleSigned, "PIX_TRANSFER", payload.fields)
        assertTrue(staleVerdict.findings.any { it.code == FindingCode.BINDING_NOT_FOUND_OR_INACTIVE })

        // Explicit revocation of the active binding (stolen phone)
        assertTrue(verifier.revokeBinding(secondBindingId))
        assertFalse(verifier.revokeBinding(firstBindingId)) // already revoked
        assertTrue(verifier.getActiveBindings("acct-attack").isEmpty())
    }

    @Test
    fun detectsAndRejectsSuspiciousBurstKeyboxFanOut() {
        val factoryRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = false)
        val sharedLeakedBatch =
            TestPkiFixture.createIntermediateCa(fixedNow, factoryRoot, isP384 = false, BigInteger("99999"))
        val verifier =
            MaigBindVerifier(
                policy =
                    VerificationPolicy(
                        keyboxSuspicionThreshold = 3,
                        keyboxSuspicionWindowMinutes = 10L,
                        rejectOnSuspiciousKeybox = true,
                    ),
                trustStoreProvider = StaticTrustStoreProvider(listOf(factoryRoot.cert)),
                revocationStatusProvider = StaticRevocationStatusProvider(),
                clock = fixedClock,
            )

        repeat(2) { idx ->
            val (_, resp) =
                attestWithIssuer(
                    verifier = verifier,
                    accountId = "acct-$idx",
                    issuer = sharedLeakedBatch,
                    issuerSigAlg = "SHA256withRSA",
                    serial = BigInteger.valueOf(200L + idx),
                    appPkg = officialApp.packageName,
                    appDigest = officialApp.signingCertSha256Digests.first(),
                    includeIssuerInChain = true,
                )
            assertTrue(resp.verdict.isVerified)
        }

        val (_, resp3) =
            attestWithIssuer(
                verifier = verifier,
                accountId = "acct-2",
                issuer = sharedLeakedBatch,
                issuerSigAlg = "SHA256withRSA",
                serial = BigInteger.valueOf(202L),
                appPkg = officialApp.packageName,
                appDigest = officialApp.signingCertSha256Digests.first(),
                includeIssuerInChain = true,
            )
        assertFalse(resp3.verdict.isVerified)
        assertTrue(resp3.verdict.findings.any { it.code == FindingCode.SUSPICIOUS_KEYBOX_FANOUT })
    }

    private fun attestWithIssuer(
        verifier: MaigBindVerifier,
        accountId: String,
        issuer: TestCaBundle,
        issuerSigAlg: String,
        serial: BigInteger,
        appPkg: String,
        appDigest: ByteArray,
        includeIssuerInChain: Boolean = false,
    ): Pair<String, io.github.maignardi.maigbind.core.EnrollmentAttestResponse> {
        val ch = verifier.beginEnrollment(accountId)
        val kp = TestPkiFixture.generateP256KeyPair()
        val keyId = computeKeyId(kp.public.encoded)
        val leaf =
            TestPkiFixture.createAttestedLeaf(
                now = fixedNow,
                issuerCert = issuer.cert,
                issuerKey = issuer.keyPair.private,
                issuerSigAlg = issuerSigAlg,
                leafKeyPair = kp,
                serial = serial,
                challenge = Base64Url.decode(ch.challengeBase64Url),
                appPkg = appPkg,
                appSigDigest = appDigest,
            )
        val chain = if (includeIssuerInChain) listOf(leaf, issuer.cert) else listOf(leaf)
        val resp =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    accountId = accountId,
                    keyId = keyId,
                    publicKeySpkiBase64Url = Base64Url.encode(kp.public.encoded),
                    attestationChainBase64Url = chain.map { Base64Url.encode(it.encoded) },
                    challengeBase64Url = ch.challengeBase64Url,
                    securityBacking = SecurityBacking.TEE,
                ),
            )
        return keyId to resp
    }

    private fun enroll(
        verifier: MaigBindVerifier,
        root: TestCaBundle,
        accountId: String,
    ): Triple<KeyPair, String, String> {
        val ch = verifier.beginEnrollment(accountId)
        val kp = TestPkiFixture.generateP256KeyPair()
        val keyId = computeKeyId(kp.public.encoded)
        val leaf =
            TestPkiFixture.createAttestedLeaf(
                now = fixedNow,
                issuerCert = root.cert,
                issuerKey = root.keyPair.private,
                issuerSigAlg = "SHA384withECDSA",
                leafKeyPair = kp,
                serial = BigInteger.valueOf(500L),
                challenge = Base64Url.decode(ch.challengeBase64Url),
                appPkg = officialApp.packageName,
                appSigDigest = officialApp.signingCertSha256Digests.first(),
            )
        val attest =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    accountId = accountId,
                    keyId = keyId,
                    publicKeySpkiBase64Url = Base64Url.encode(kp.public.encoded),
                    attestationChainBase64Url = listOf(Base64Url.encode(leaf.encoded)),
                    challengeBase64Url = ch.challengeBase64Url,
                    securityBacking = SecurityBacking.TEE,
                ),
            )
        val pop =
            EnrollmentPoPPayload(
                keyId = keyId,
                accountId = accountId,
                challenge = attest.popChallengeBase64Url,
                issuedAt = fixedNow.toEpochMilli(),
                expiresAt = attest.popExpiresAt,
            )
        val confirm =
            verifier.confirmEnrollmentPop(
                EnrollmentConfirmRequest(
                    bindingId = attest.bindingId,
                    popPayload = pop,
                    signatureBase64Url = Base64Url.encode(TestPkiFixture.ecdsaSign(kp.private, pop.signingInput())),
                ),
            )
        assertEquals(EnrollmentStatus.ACTIVE, confirm.status)
        return Triple(kp, keyId, attest.bindingId)
    }
}
