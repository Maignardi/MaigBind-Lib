package io.github.maignardi.maigbind.verifier

import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.DomainTag
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
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Date

class MaigBindVerifierTest {
    private val fixedNow = Instant.parse("2026-11-18T12:00:00Z")
    private val fixedClock = Clock.fixed(fixedNow, ZoneOffset.UTC)
    private val appPkg = "com.example.bank"
    private val appCertDigest = Sha256.digest("official-release-signing-cert".encodeToByteArray())
    private val expectedApp = ExpectedAndroidApp(appPkg, setOf(appCertDigest))

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Test
    fun embeddedGoogleRootsLoadBothLegacyRsaAndRkpEcdsaP384() {
        val roots = EmbeddedGoogleRoots.loadFallbackCertificates()
        assertEquals(2, roots.size)
        assertFalse(EmbeddedGoogleRoots.isRkpRoot(roots[0]))
        assertTrue(EmbeddedGoogleRoots.isRkpRoot(roots[1]))
    }

    @Test
    fun revocationCheckerHandlesBothDecimalAndHexSerialsFromGoogleFeed() {
        val rkpCa = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = true)
        val leafPair = TestPkiFixture.generateP256KeyPair()
        val entries =
            mapOf(
                "6681152659205225093" to StatusFeedEntry(status = "REVOKED", reason = "KEY_COMPROMISE"),
                "2c8cdddfd5e03bfc" to StatusFeedEntry(status = "SUSPENDED", reason = "SOFTWARE_FLAW"),
            )
        val decimalLeaf =
            TestPkiFixture.createAttestedLeaf(
                fixedNow,
                rkpCa.cert,
                rkpCa.keyPair.private,
                "SHA384withECDSA",
                leafPair,
                BigInteger("6681152659205225093"),
                ByteArray(32),
                appPkg,
                appCertDigest,
            )
        assertTrue(
            GoogleRevocationStatusProvider.checkCertificatesAgainstEntries(
                listOf(decimalLeaf),
                entries,
            ) is RevocationCheckResult.Revoked,
        )

        val hexLeaf =
            TestPkiFixture.createAttestedLeaf(
                fixedNow,
                rkpCa.cert,
                rkpCa.keyPair.private,
                "SHA384withECDSA",
                leafPair,
                BigInteger("2c8cdddfd5e03bfc", 16),
                ByteArray(32),
                appPkg,
                appCertDigest,
            )
        assertTrue(
            GoogleRevocationStatusProvider.checkCertificatesAgainstEntries(
                listOf(hexLeaf),
                entries,
            ) is RevocationCheckResult.Revoked,
        )
    }

    @Test
    fun fullRkpP384EnrollmentWithImmediatePopAndTransactionVerificationSucceeds() {
        val rkpRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = true)
        val intermediate =
            TestPkiFixture.createIntermediateCa(
                fixedNow,
                rkpRoot,
                isP384 = true,
                BigInteger.valueOf(1001L),
            )
        val verifier =
            createVerifier(
                roots = listOf(rkpRoot.cert),
                policy = VerificationPolicy(expectedApps = listOf(expectedApp), allowFactoryKeys = false),
            )
        val ch = verifier.beginEnrollment("acct-1")
        val devKey = TestPkiFixture.generateP256KeyPair()
        val leaf =
            TestPkiFixture.createAttestedLeaf(
                fixedNow,
                intermediate.cert,
                intermediate.keyPair.private,
                "SHA384withECDSA",
                devKey,
                BigInteger.valueOf(9001L),
                Base64Url.decode(ch.challengeBase64Url),
                appPkg,
                appCertDigest,
                attestationSecLevel = 2,
                keymasterSecLevel = 2,
            )
        val keyId = computeKeyId(devKey.public.encoded)
        val attestResp =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    "acct-1",
                    keyId,
                    Base64Url.encode(devKey.public.encoded),
                    listOf(leaf, intermediate.cert).map { Base64Url.encode(it.encoded) },
                    ch.challengeBase64Url,
                    SecurityBacking.STRONGBOX,
                ),
            )
        assertTrue(attestResp.verdict.isVerified)
        assertEquals(EnrollmentStatus.PENDING_POP, attestResp.status)
        assertEquals(true, attestResp.verdict.isRkpChain)
        assertEquals(SecurityBacking.STRONGBOX, attestResp.verdict.securityBacking)

        // Transaction before PoP confirmation must fail
        val prePop =
            TestPkiFixture.signSampleTx(
                devKey,
                keyId,
                "dummy",
                fixedNow.toEpochMilli(),
                fixedNow.plusSeconds(60).toEpochMilli(),
            )
        val prePopVerdict = verifier.verifyTransaction("acct-1", prePop, "PIX_TRANSFER", prePop.payload.fields)
        assertEquals(VerdictStatus.REJECTED_FRAUD_SIGNAL, prePopVerdict.status)
        assertTrue(prePopVerdict.findings.any { it.code == FindingCode.BINDING_NOT_FOUND_OR_INACTIVE })

        val popPayload =
            EnrollmentPoPPayload(
                keyId = keyId,
                accountId = "acct-1",
                challenge = attestResp.popChallengeBase64Url,
                issuedAt = fixedNow.toEpochMilli(),
                expiresAt = attestResp.popExpiresAt,
            )
        val confirmResp =
            verifier.confirmEnrollmentPop(
                EnrollmentConfirmRequest(
                    attestResp.bindingId,
                    popPayload,
                    Base64Url.encode(TestPkiFixture.ecdsaSign(devKey.private, popPayload.signingInput())),
                ),
            )
        assertEquals(EnrollmentStatus.ACTIVE, confirmResp.status)

        val txCh = verifier.issueTransactionNonce("acct-1", keyId)
        val signedTx = TestPkiFixture.signSampleTx(devKey, keyId, txCh.nonceBase64Url, txCh.issuedAt, txCh.expiresAt)
        val txVerdict = verifier.verifyTransaction("acct-1", signedTx, "PIX_TRANSFER", signedTx.payload.fields)
        assertTrue(txVerdict.isVerified)
    }

    @Test
    fun rejectsUntrustedRootChain() {
        val trustedRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = true)
        val rogueRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = true, cn = "Rogue Attestation CA")
        val verifier = createVerifier(roots = listOf(trustedRoot.cert))
        val ch = verifier.beginEnrollment("acct-1")
        val devKey = TestPkiFixture.generateP256KeyPair()
        val leaf =
            TestPkiFixture.createAttestedLeaf(
                fixedNow,
                rogueRoot.cert,
                rogueRoot.keyPair.private,
                "SHA384withECDSA",
                devKey,
                BigInteger.ONE,
                Base64Url.decode(ch.challengeBase64Url),
                appPkg,
                appCertDigest,
            )
        val resp =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    "acct-1",
                    computeKeyId(devKey.public.encoded),
                    Base64Url.encode(devKey.public.encoded),
                    listOf(leaf, rogueRoot.cert).map { Base64Url.encode(it.encoded) },
                    ch.challengeBase64Url,
                    SecurityBacking.TEE,
                ),
            )
        assertEquals(VerdictStatus.REJECTED_FRAUD_SIGNAL, resp.verdict.status)
        assertTrue(resp.verdict.findings.any { it.code == FindingCode.CERT_CHAIN_UNTRUSTED_ROOT })
    }

    @Test
    fun rejectsRevokedKeyboxCertificate() {
        val rsaRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = false)
        val intermediate = TestPkiFixture.createIntermediateCa(fixedNow, rsaRoot, isP384 = false, BigInteger("777777"))
        val verifier =
            createVerifier(
                roots = listOf(rsaRoot.cert),
                revocationProvider = StaticRevocationStatusProvider(mapOf("777777" to ("REVOKED" to "KEY_COMPROMISE"))),
            )
        val ch = verifier.beginEnrollment("acct-1")
        val devKey = TestPkiFixture.generateP256KeyPair()
        val leaf =
            TestPkiFixture.createAttestedLeaf(
                fixedNow,
                intermediate.cert,
                intermediate.keyPair.private,
                "SHA256withRSA",
                devKey,
                BigInteger.TEN,
                Base64Url.decode(ch.challengeBase64Url),
                appPkg,
                appCertDigest,
            )
        val resp =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    "acct-1",
                    computeKeyId(devKey.public.encoded),
                    Base64Url.encode(devKey.public.encoded),
                    listOf(leaf, intermediate.cert).map { Base64Url.encode(it.encoded) },
                    ch.challengeBase64Url,
                    SecurityBacking.TEE,
                ),
            )
        assertEquals(VerdictStatus.REJECTED_FRAUD_SIGNAL, resp.verdict.status)
        assertTrue(resp.verdict.findings.any { it.code == FindingCode.CERT_REVOKED_OR_SUSPENDED })
    }

    @Test
    fun rejectsWrongChallengeSoftwareLevelUnlockedBootAndWrongPackage() {
        val rkpRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = true)
        val verifier =
            createVerifier(
                roots = listOf(rkpRoot.cert),
                policy = VerificationPolicy(expectedApps = listOf(expectedApp), minOsPatchLevel = 202601),
            )
        val ch = verifier.beginEnrollment("acct-1")
        val devKey = TestPkiFixture.generateP256KeyPair()
        val leaf =
            TestPkiFixture.createAttestedLeaf(
                now = fixedNow,
                issuerCert = rkpRoot.cert,
                issuerKey = rkpRoot.keyPair.private,
                issuerSigAlg = "SHA384withECDSA",
                leafKeyPair = devKey,
                serial = BigInteger.valueOf(42L),
                challenge = "wrong-challenge-bytes".encodeToByteArray(),
                appPkg = "com.evil.clone",
                appSigDigest = Sha256.digest("evil-cert".encodeToByteArray()),
                attestationSecLevel = 0,
                keymasterSecLevel = 0,
                deviceLocked = false,
                verifiedBootState = 2,
                noAuthRequired = true,
                userAuthType = 1L,
                authTimeout = 30L,
                osPatchLevel = 202401,
            )
        val resp =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    "acct-1",
                    computeKeyId(devKey.public.encoded),
                    Base64Url.encode(devKey.public.encoded),
                    listOf(Base64Url.encode(leaf.encoded)),
                    ch.challengeBase64Url,
                    SecurityBacking.UNKNOWN,
                ),
            )
        val codes =
            resp.verdict.findings
                .map { it.code }
                .toSet()
        assertEquals(VerdictStatus.REJECTED_FRAUD_SIGNAL, resp.verdict.status)
        assertTrue(FindingCode.ATTESTATION_CHALLENGE_MISMATCH in codes)
        assertTrue(FindingCode.ATTESTATION_SECURITY_LEVEL_TOO_LOW in codes)
        assertTrue(FindingCode.KEYMASTER_SECURITY_LEVEL_TOO_LOW in codes)
        assertTrue(FindingCode.BOOTLOADER_UNLOCKED_OR_UNVERIFIED in codes)
        assertTrue(FindingCode.KEY_NO_AUTH_REQUIRED_PRESENT in codes)
        assertTrue(FindingCode.KEY_AUTH_TYPE_NOT_BIOMETRIC in codes)
        assertTrue(FindingCode.KEY_AUTH_TIMEOUT_NOT_PER_USE in codes)
        assertTrue(FindingCode.OS_PATCH_LEVEL_TOO_LOW in codes)
        assertTrue(FindingCode.APP_IDENTITY_MISMATCH in codes)
    }

    @Test
    fun rejectsExpiredCertificateChain() {
        val rkpRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = true)
        val verifier = createVerifier(roots = listOf(rkpRoot.cert))
        val ch = verifier.beginEnrollment("acct-1")
        val devKey = TestPkiFixture.generateP256KeyPair()
        val expiredLeaf =
            TestPkiFixture.createAttestedLeaf(
                fixedNow,
                rkpRoot.cert,
                rkpRoot.keyPair.private,
                "SHA384withECDSA",
                devKey,
                BigInteger.valueOf(55L),
                Base64Url.decode(ch.challengeBase64Url),
                appPkg,
                appCertDigest,
                notBefore = Date.from(fixedNow.minus(Duration.ofDays(10))),
                notAfter = Date.from(fixedNow.minus(Duration.ofDays(1))),
            )
        val resp =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    "acct-1",
                    computeKeyId(devKey.public.encoded),
                    Base64Url.encode(devKey.public.encoded),
                    listOf(Base64Url.encode(expiredLeaf.encoded)),
                    ch.challengeBase64Url,
                    SecurityBacking.TEE,
                ),
            )
        assertEquals(VerdictStatus.REJECTED_FRAUD_SIGNAL, resp.verdict.status)
        assertTrue(resp.verdict.findings.any { it.code == FindingCode.CERT_CHAIN_EXPIRED_OR_NOT_YET_VALID })
    }

    @Test
    fun rejectsNonceReplayTamperedPayloadAndCrossDomainSignature() {
        val (verifier, keyPair, keyId) = enrollActiveDevice()

        val txNonce = verifier.issueTransactionNonce("acct-1", keyId)
        val tx =
            TransactionPayload(
                keyId = keyId,
                operationType = "PIX_TRANSFER",
                nonce = txNonce.nonceBase64Url,
                issuedAt = txNonce.issuedAt,
                expiresAt = txNonce.expiresAt,
                fields = canonicalFields("amountCents" to canonical(5000L)),
            )
        val wrongDomainSig =
            TestPkiFixture.ecdsaSign(
                keyPair.private,
                DomainTag.ENROLL_POP.wrap(tx.toCanonicalCborBytes()),
            )
        val wrongDomainVerdict =
            verifier.verifyTransaction(
                "acct-1",
                SignedPayload(tx, Base64Url.encode(wrongDomainSig)),
                "PIX_TRANSFER",
                tx.fields,
            )
        assertTrue(wrongDomainVerdict.findings.any { it.code == FindingCode.SIGNATURE_INVALID })

        val txNonce2 = verifier.issueTransactionNonce("acct-1", keyId)
        val validSigned =
            TestPkiFixture.signSampleTx(
                keyPair,
                keyId,
                txNonce2.nonceBase64Url,
                txNonce2.issuedAt,
                txNonce2.expiresAt,
            )
        assertTrue(
            verifier.verifyTransaction("acct-1", validSigned, "PIX_TRANSFER", validSigned.payload.fields).isVerified,
        )
        val replayVerdict =
            verifier.verifyTransaction(
                "acct-1",
                validSigned,
                "PIX_TRANSFER",
                validSigned.payload.fields,
            )
        assertTrue(replayVerdict.findings.any { it.code == FindingCode.NONCE_REPLAYED_OR_UNKNOWN })

        val txNonce3 = verifier.issueTransactionNonce("acct-1", keyId)
        val signedFor150 =
            TestPkiFixture.signSampleTx(
                keyPair,
                keyId,
                txNonce3.nonceBase64Url,
                txNonce3.issuedAt,
                txNonce3.expiresAt,
            )
        val tamperedVerdict =
            verifier.verifyTransaction(
                "acct-1",
                signedFor150,
                "PIX_TRANSFER",
                canonicalFields(
                    "amountCents" to canonical(9_999_900L),
                    "currency" to canonical("BRL"),
                    "recipient" to canonical("attacker@evil.example"),
                ),
            )
        assertTrue(tamperedVerdict.findings.any { it.code == FindingCode.PAYLOAD_FIELD_MISMATCH })
    }

    @Test
    fun distinguishesInfraFailureWithFailClosedVsFailOpen() {
        val rkpRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = true)
        val closedVerifier =
            createVerifier(
                roots = listOf(rkpRoot.cert),
                revocationProvider = StaticRevocationStatusProvider(simulateUnavailable = true),
                policy = VerificationPolicy(failMode = FailMode.FAIL_CLOSED),
            )
        val ch1 = closedVerifier.beginEnrollment("acct-1")
        val k1 = TestPkiFixture.generateP256KeyPair()
        val leaf1 =
            TestPkiFixture.createAttestedLeaf(
                fixedNow,
                rkpRoot.cert,
                rkpRoot.keyPair.private,
                "SHA384withECDSA",
                k1,
                BigInteger.valueOf(71L),
                Base64Url.decode(ch1.challengeBase64Url),
                appPkg,
                appCertDigest,
            )
        val closedResp =
            closedVerifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    "acct-1",
                    computeKeyId(k1.public.encoded),
                    Base64Url.encode(k1.public.encoded),
                    listOf(Base64Url.encode(leaf1.encoded)),
                    ch1.challengeBase64Url,
                    SecurityBacking.TEE,
                ),
            )
        assertEquals(VerdictStatus.ERROR_VALIDATION_INFRA, closedResp.verdict.status)

        val openVerifier =
            createVerifier(
                roots = listOf(rkpRoot.cert),
                revocationProvider = StaticRevocationStatusProvider(simulateUnavailable = true),
                policy = VerificationPolicy(failMode = FailMode.FAIL_OPEN),
            )
        val ch2 = openVerifier.beginEnrollment("acct-2")
        val k2 = TestPkiFixture.generateP256KeyPair()
        val leaf2 =
            TestPkiFixture.createAttestedLeaf(
                fixedNow,
                rkpRoot.cert,
                rkpRoot.keyPair.private,
                "SHA384withECDSA",
                k2,
                BigInteger.valueOf(72L),
                Base64Url.decode(ch2.challengeBase64Url),
                appPkg,
                appCertDigest,
            )
        val openResp =
            openVerifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    "acct-2",
                    computeKeyId(k2.public.encoded),
                    Base64Url.encode(k2.public.encoded),
                    listOf(Base64Url.encode(leaf2.encoded)),
                    ch2.challengeBase64Url,
                    SecurityBacking.TEE,
                ),
            )
        assertTrue(openResp.verdict.isVerified)
        assertTrue(openResp.verdict.findings.any { it.code == FindingCode.INFRA_FAIL_OPEN_APPLIED })
    }

    private fun enrollActiveDevice(): Triple<MaigBindVerifier, KeyPair, String> {
        val rkpRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = true)
        val verifier = createVerifier(roots = listOf(rkpRoot.cert))
        val ch = verifier.beginEnrollment("acct-1")
        val keyPair = TestPkiFixture.generateP256KeyPair()
        val keyId = computeKeyId(keyPair.public.encoded)
        val leaf =
            TestPkiFixture.createAttestedLeaf(
                fixedNow,
                rkpRoot.cert,
                rkpRoot.keyPair.private,
                "SHA384withECDSA",
                keyPair,
                BigInteger.valueOf(88L),
                Base64Url.decode(ch.challengeBase64Url),
                appPkg,
                appCertDigest,
            )
        val attest =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    "acct-1",
                    keyId,
                    Base64Url.encode(keyPair.public.encoded),
                    listOf(Base64Url.encode(leaf.encoded)),
                    ch.challengeBase64Url,
                    SecurityBacking.TEE,
                ),
            )
        val popPayload =
            EnrollmentPoPPayload(
                keyId = keyId,
                accountId = "acct-1",
                challenge = attest.popChallengeBase64Url,
                issuedAt = fixedNow.toEpochMilli(),
                expiresAt = attest.popExpiresAt,
            )
        val confirm =
            verifier.confirmEnrollmentPop(
                EnrollmentConfirmRequest(
                    attest.bindingId,
                    popPayload,
                    Base64Url.encode(TestPkiFixture.ecdsaSign(keyPair.private, popPayload.signingInput())),
                ),
            )
        assertEquals(EnrollmentStatus.ACTIVE, confirm.status)
        return Triple(verifier, keyPair, keyId)
    }

    private fun createVerifier(
        roots: List<X509Certificate>,
        revocationProvider: RevocationStatusProvider = StaticRevocationStatusProvider(),
        policy: VerificationPolicy = VerificationPolicy(),
    ): MaigBindVerifier =
        MaigBindVerifier(
            policy = policy,
            trustStoreProvider = StaticTrustStoreProvider(roots),
            revocationStatusProvider = revocationProvider,
            clock = fixedClock,
        )
}
