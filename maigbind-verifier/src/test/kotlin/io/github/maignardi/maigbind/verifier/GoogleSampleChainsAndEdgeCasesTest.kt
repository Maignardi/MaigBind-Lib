package io.github.maignardi.maigbind.verifier

import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.EnrollmentRequest
import io.github.maignardi.maigbind.core.FindingCode
import io.github.maignardi.maigbind.core.FindingSeverity
import io.github.maignardi.maigbind.core.SecurityBacking
import io.github.maignardi.maigbind.core.Sha256
import io.github.maignardi.maigbind.core.VerdictStatus
import io.github.maignardi.maigbind.core.computeKeyId
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.Date
import java.util.concurrent.ConcurrentHashMap

/**
 * Tests against real Google-published hardware key attestation chains (Pixel 9 Pro RKP StrongBox
 * and Pixel 3 Factory TEE from `github.com/android/keyattestation/testdata`), plus RedisNonceStore
 * and strict VerificationPolicy edge cases.
 */
class GoogleSampleChainsAndEdgeCasesTest {
    private val fixedNow = Instant.parse("2026-11-18T12:00:00Z")
    private val fixedClock = Clock.fixed(fixedNow, ZoneOffset.UTC)

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Test
    fun parsesAndValidatesRealGoogleCaimanSdk36StrongBoxRkpChain() {
        val chain = loadPemChain("/google_samples/caiman_sdk36_SB_EC_RKP.pem")
        assertEquals(5, chain.size)

        val leaf = chain.first()
        val record = KeyAttestationParser.parseOrNull(leaf)
        assertNotNull(record)
        record!!

        // Assert parsed extension matches Google's official caiman/sdk36/SB_EC_RKP.json fixture
        assertEquals(300, record.attestationVersion)
        assertEquals(AttestationSecurityLevel.STRONG_BOX, record.attestationSecurityLevel)
        assertEquals(300, record.keymasterVersion)
        assertEquals(AttestationSecurityLevel.STRONG_BOX, record.keymasterSecurityLevel)
        assertEquals(
            "7ccac1ea-4845-482e-858d-f6fa9aa8c295",
            record.attestationChallenge.decodeToString(),
        )

        val hw = record.hardwareEnforced
        assertEquals(setOf(2, 3), hw.purposes)
        assertEquals(3, hw.algorithm)
        assertEquals(256, hw.keySize)
        assertEquals(1, hw.ecCurve)
        assertTrue(hw.noAuthRequired)
        assertEquals(160000, hw.osVersion)
        assertEquals(202511, hw.osPatchLevel)
        assertEquals(20251105, hw.vendorPatchLevel)
        assertEquals(20251105, hw.bootPatchLevel)
        val rot = hw.rootOfTrust
        assertNotNull(rot)
        assertTrue(rot!!.deviceLocked)
        assertEquals(VerifiedBootState.VERIFIED, rot.verifiedBootState)

        val appId = record.softwareEnforced.attestationApplicationId
        assertNotNull(appId)
        assertEquals("com.google.android.attestation", appId!!.packages.single().packageName)
        assertArrayEquals(
            Base64.getDecoder().decode("EDk47kU35Z6O55L2VFBPuDRvxrNG0LvEQV/DOfz8jsE="),
            appId.signatureDigests.single(),
        )

        // Verify PKIX chain at an instant inside all certs' validity windows
        // (leaf certs often have notBefore = 1970-01-01, while RKP intermediates are short-lived)
        val validAt = chain.maxOf { it.notBefore.toInstant() }.plusSeconds(60)
        val sampleValidClock = Clock.fixed(validAt, ZoneOffset.UTC)
        val validator =
            AttestationValidator(
                policy = VerificationPolicy(),
                trustStoreProvider = StaticTrustStoreProvider(listOf(chain.last())),
                revocationStatusProvider = StaticRevocationStatusProvider(),
            )
        val findings = mutableListOf<io.github.maignardi.maigbind.core.Finding>()
        val pkix = validator.validatePkixChain(chain, Date.from(sampleValidClock.instant()), findings)
        assertNotNull(pkix.matchedRoot)
        assertTrue("Expected no PKIX findings, got $findings", findings.isEmpty())

        // Run through full MaigBindVerifier: because this Google sample key has noAuthRequired=true,
        // MaigBindVerifier MUST reject it for biometric-bound banking operations!
        assertCaimanNoAuthRejected(chain, leaf, record.attestationChallenge, sampleValidClock)
    }

    private fun assertCaimanNoAuthRejected(
        chain: List<X509Certificate>,
        leaf: X509Certificate,
        challenge: ByteArray,
        sampleValidClock: Clock,
    ) {
        val challengeStore =
            InMemoryChallengeStore().apply {
                saveChallenge("enroll::caiman-user", challenge, sampleValidClock.millis() + 60_000L)
            }
        val verifier =
            MaigBindVerifier(
                policy = VerificationPolicy(),
                trustStoreProvider = StaticTrustStoreProvider(listOf(chain.last())),
                revocationStatusProvider = StaticRevocationStatusProvider(),
                challengeStore = challengeStore,
                clock = sampleValidClock,
            )
        val resp =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    accountId = "caiman-user",
                    keyId = computeKeyId(leaf.publicKey.encoded),
                    publicKeySpkiBase64Url = Base64Url.encode(leaf.publicKey.encoded),
                    attestationChainBase64Url = chain.map { Base64Url.encode(it.encoded) },
                    challengeBase64Url = Base64Url.encode(challenge),
                    securityBacking = SecurityBacking.STRONGBOX,
                ),
            )
        assertEquals(VerdictStatus.REJECTED_FRAUD_SIGNAL, resp.verdict.status)
        val codes =
            resp.verdict.findings
                .map { it.code }
                .toSet()
        assertTrue(FindingCode.KEY_NO_AUTH_REQUIRED_PRESENT in codes)
        assertTrue(FindingCode.KEY_AUTH_TYPE_NOT_BIOMETRIC in codes)
    }

    @Test
    fun parsesAndValidatesRealGoogleBluelineSdk28TeeChain() {
        val chain = loadPemChain("/google_samples/blueline_sdk28_TEE_EC_NONE.pem")
        assertEquals(4, chain.size)

        val leaf = chain.first()
        val record = KeyAttestationParser.parseOrNull(leaf)
        assertNotNull(record)
        assertEquals(AttestationSecurityLevel.TRUSTED_ENVIRONMENT, record!!.attestationSecurityLevel)
        assertEquals(AttestationSecurityLevel.TRUSTED_ENVIRONMENT, record.keymasterSecurityLevel)
        assertEquals(false, record.hardwareEnforced.rootOfTrust?.deviceLocked)
        assertEquals(VerifiedBootState.UNVERIFIED, record.hardwareEnforced.rootOfTrust?.verifiedBootState)

        val validAt = chain.maxOf { it.notBefore.toInstant() }.plusSeconds(60)
        val validator =
            AttestationValidator(
                policy = VerificationPolicy(),
                trustStoreProvider = StaticTrustStoreProvider(listOf(chain.last())),
                revocationStatusProvider = StaticRevocationStatusProvider(),
            )
        val findings = mutableListOf<io.github.maignardi.maigbind.core.Finding>()
        val pkix = validator.validatePkixChain(chain, Date.from(validAt), findings)
        assertNotNull(pkix.matchedRoot)
        assertTrue("Expected clean PKIX validation on real Google chain, got $findings", findings.isEmpty())
    }

    @Test
    fun policyRejectsFactoryKeysStrongBoxMissingAndLeafPublicKeyMismatch() {
        val factoryRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = false)
        val rkpRequiredVerifier =
            MaigBindVerifier(
                policy = VerificationPolicy(allowFactoryKeys = false, requireStrongBox = true),
                trustStoreProvider = StaticTrustStoreProvider(listOf(factoryRoot.cert)),
                revocationStatusProvider = StaticRevocationStatusProvider(),
                clock = fixedClock,
            )
        val ch = rkpRequiredVerifier.beginEnrollment("acct-policy")
        val devKey = TestPkiFixture.generateP256KeyPair()
        val otherKey = TestPkiFixture.generateP256KeyPair()

        // Valid TEE factory leaf, but submitted with mismatched SPKI and violating RKP + StrongBox policy
        val leaf =
            TestPkiFixture.createAttestedLeaf(
                now = fixedNow,
                issuerCert = factoryRoot.cert,
                issuerKey = factoryRoot.keyPair.private,
                issuerSigAlg = "SHA256withRSA",
                leafKeyPair = devKey,
                serial = BigInteger.valueOf(301L),
                challenge = Base64Url.decode(ch.challengeBase64Url),
                appPkg = "com.example.bank",
                appSigDigest = Sha256.digest("sig".encodeToByteArray()),
                attestationSecLevel = 1, // TEE
                keymasterSecLevel = 1, // TEE
            )
        val resp =
            rkpRequiredVerifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    accountId = "acct-policy",
                    keyId = computeKeyId(otherKey.public.encoded),
                    publicKeySpkiBase64Url = Base64Url.encode(otherKey.public.encoded),
                    attestationChainBase64Url = listOf(Base64Url.encode(leaf.encoded)),
                    challengeBase64Url = ch.challengeBase64Url,
                    securityBacking = SecurityBacking.TEE,
                ),
            )
        val codes =
            resp.verdict.findings
                .map { it.code }
                .toSet()
        assertFalse(resp.verdict.isVerified)
        assertTrue(FindingCode.FACTORY_KEY_NOT_ALLOWED in codes)
        assertTrue(FindingCode.STRONGBOX_REQUIRED in codes)
        assertTrue(FindingCode.LEAF_PUBLIC_KEY_MISMATCH in codes)

        // Also test REJECTED_POLICY classification when only policy checks fail (matching SPKI)
        val ch2 = rkpRequiredVerifier.beginEnrollment("acct-policy-2")
        val leaf2 =
            TestPkiFixture.createAttestedLeaf(
                now = fixedNow,
                issuerCert = factoryRoot.cert,
                issuerKey = factoryRoot.keyPair.private,
                issuerSigAlg = "SHA256withRSA",
                leafKeyPair = devKey,
                serial = BigInteger.valueOf(302L),
                challenge = Base64Url.decode(ch2.challengeBase64Url),
                appPkg = "com.example.bank",
                appSigDigest = Sha256.digest("sig".encodeToByteArray()),
                attestationSecLevel = 1,
                keymasterSecLevel = 1,
            )
        val policyOnlyResp =
            rkpRequiredVerifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    accountId = "acct-policy-2",
                    keyId = computeKeyId(devKey.public.encoded),
                    publicKeySpkiBase64Url = Base64Url.encode(devKey.public.encoded),
                    attestationChainBase64Url = listOf(Base64Url.encode(leaf2.encoded)),
                    challengeBase64Url = ch2.challengeBase64Url,
                    securityBacking = SecurityBacking.TEE,
                ),
            )
        assertEquals(VerdictStatus.REJECTED_POLICY, policyOnlyResp.verdict.status)
    }

    @Test
    fun suspiciousKeyboxFanOutEmitsWarningWithoutBlockingWhenRejectFalse() {
        val factoryRoot = TestPkiFixture.createRootCa(fixedNow, isRkpP384 = false)
        val sharedIntermediate =
            TestPkiFixture.createIntermediateCa(
                now = fixedNow,
                parent = factoryRoot,
                isP384 = false,
                serial = BigInteger.valueOf(8888L),
            )
        val verifier =
            MaigBindVerifier(
                policy = VerificationPolicy(keyboxSuspicionThreshold = 2, rejectOnSuspiciousKeybox = false),
                trustStoreProvider = StaticTrustStoreProvider(listOf(factoryRoot.cert)),
                revocationStatusProvider = StaticRevocationStatusProvider(),
                clock = fixedClock,
            )

        repeat(2) { idx ->
            val acct = "warn-acct-$idx"
            val ch = verifier.beginEnrollment(acct)
            val kp = TestPkiFixture.generateP256KeyPair()
            val leaf =
                TestPkiFixture.createAttestedLeaf(
                    now = fixedNow,
                    issuerCert = sharedIntermediate.cert,
                    issuerKey = sharedIntermediate.keyPair.private,
                    issuerSigAlg = "SHA256withRSA",
                    leafKeyPair = kp,
                    serial = BigInteger.valueOf(400L + idx),
                    challenge = Base64Url.decode(ch.challengeBase64Url),
                    appPkg = "com.example.bank",
                    appSigDigest = Sha256.digest("sig".encodeToByteArray()),
                )
            val resp =
                verifier.verifyEnrollmentAttestation(
                    EnrollmentRequest(
                        accountId = acct,
                        keyId = computeKeyId(kp.public.encoded),
                        publicKeySpkiBase64Url = Base64Url.encode(kp.public.encoded),
                        attestationChainBase64Url =
                            listOf(
                                leaf,
                                sharedIntermediate.cert,
                            ).map { Base64Url.encode(it.encoded) },
                        challengeBase64Url = ch.challengeBase64Url,
                        securityBacking = SecurityBacking.TEE,
                    ),
                )
            assertTrue(resp.verdict.isVerified)
            if (idx == 1) {
                val finding = resp.verdict.findings.firstOrNull { it.code == FindingCode.SUSPICIOUS_KEYBOX_FANOUT }
                assertNotNull(finding)
                assertEquals(FindingSeverity.WARNING, finding!!.severity)
            }
        }
    }

    @Test
    fun redisNonceStoreEnforcesAtomicSingleUseAndTtlExpiry() {
        val fakeRedisMap = ConcurrentHashMap<String, String>()
        val redis =
            object : RedisCommands {
                override fun setWithTtlMillis(
                    key: String,
                    value: String,
                    ttlMillis: Long,
                ): Boolean {
                    fakeRedisMap[key] = value
                    return true
                }

                override fun getAndDelete(key: String): String? = fakeRedisMap.remove(key)
            }
        val store = RedisNonceStore(redis)
        val now = System.currentTimeMillis()
        store.issueNonce("key-1", "nonce-abc", now + 30_000L)
        assertTrue(fakeRedisMap.containsKey("maigbind:nonce:nonce-abc"))

        // Wrong keyId cannot consume it
        assertFalse(store.consumeIfUnused("wrong-key", "nonce-abc", now))
        // Second attempt after removal fails
        assertFalse(store.consumeIfUnused("key-1", "nonce-abc", now))

        // Fresh nonce succeeds once and rejects replay
        store.issueNonce("key-1", "nonce-def", now + 30_000L)
        assertTrue(store.consumeIfUnused("key-1", "nonce-def", now))
        assertFalse(store.consumeIfUnused("key-1", "nonce-def", now))

        // Expired nonce fails
        store.issueNonce("key-1", "nonce-expired", now - 1_000L)
        assertFalse(store.consumeIfUnused("key-1", "nonce-expired", now))
    }

    private fun loadPemChain(resourcePath: String): List<X509Certificate> {
        val pemText =
            checkNotNull(javaClass.getResourceAsStream(resourcePath)) {
                "Missing test resource: $resourcePath"
            }.bufferedReader().use { it.readText() }
        val cf = CertificateFactory.getInstance("X.509")
        val regex = Regex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----")
        return regex
            .findAll(pemText)
            .map { match ->
                cf.generateCertificate(ByteArrayInputStream(match.value.encodeToByteArray())) as X509Certificate
            }.toList()
    }
}
