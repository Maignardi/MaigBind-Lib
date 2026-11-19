package io.github.maignardi.maigbind.verifier

import io.github.maignardi.maigbind.core.AuthPolicyUsed
import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.ClientAuthMetadata
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
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Date

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
        val root = createRootCa(isRkp = true)
        val verifier =
            MaigBindVerifier(
                policy = VerificationPolicy(expectedApps = listOf(officialApp)),
                trustStoreProvider = StaticTrustStoreProvider(listOf(root.cert)),
                revocationStatusProvider = StaticRevocationStatusProvider(),
                clock = fixedClock,
            )
        val challenge = verifier.beginEnrollment("victim-acct")

        // Scenario A: Attacker relays challenge to a third-party oracle app on a clean device
        val oracleKey = generateP256()
        val oracleLeaf =
            createLeaf(
                rootCert = root.cert,
                rootPair = root.keyPair,
                leafPair = oracleKey,
                challenge = Base64Url.decode(challenge.challengeBase64Url),
                appPkg = "com.quarkslab.attestation.oracle",
                appDigest = Sha256.digest("oracle-signer".encodeToByteArray()),
            )
        val oracleResp =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    accountId = "victim-acct",
                    keyId = computeKeyId(oracleKey.public.encoded),
                    publicKeySpkiBase64Url = Base64Url.encode(oracleKey.public.encoded),
                    attestationChainBase64Url = listOf(Base64Url.encode(oracleLeaf.encoded)),
                    challengeBase64Url = challenge.challengeBase64Url,
                    securityBacking = SecurityBacking.TEE,
                ),
            )
        assertFalse(oracleResp.verdict.isVerified)
        assertTrue(oracleResp.verdict.findings.any { it.code == FindingCode.APP_IDENTITY_MISMATCH })

        // Scenario B: Attacker uses genuine app on clean device for Step 1, tries to skip Step-2 PoP
        val ch2 = verifier.beginEnrollment("victim-acct")
        val cleanKey = generateP256()
        val cleanKeyId = computeKeyId(cleanKey.public.encoded)
        val cleanLeaf =
            createLeaf(
                rootCert = root.cert,
                rootPair = root.keyPair,
                leafPair = cleanKey,
                challenge = Base64Url.decode(ch2.challengeBase64Url),
                appPkg = officialApp.packageName,
                appDigest = officialApp.signingCertSha256Digests.first(),
            )
        val attestOk =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    accountId = "victim-acct",
                    keyId = cleanKeyId,
                    publicKeySpkiBase64Url = Base64Url.encode(cleanKey.public.encoded),
                    attestationChainBase64Url = listOf(Base64Url.encode(cleanLeaf.encoded)),
                    challengeBase64Url = ch2.challengeBase64Url,
                    securityBacking = SecurityBacking.TEE,
                ),
            )
        assertEquals(EnrollmentStatus.PENDING_POP, attestOk.status)

        // Attacker tries to sign PoP with a local rogue key because they don't possess cleanKey.private
        val rogueKey = generateP256()
        val popPayload =
            EnrollmentPoPPayload(
                keyId = cleanKeyId,
                accountId = "victim-acct",
                challenge = attestOk.popChallengeBase64Url,
                issuedAt = fixedNow.toEpochMilli(),
                expiresAt = attestOk.popExpiresAt,
            )
        val forgedPop = sign(rogueKey, popPayload.signingInput())
        val confirmResp =
            verifier.confirmEnrollmentPop(
                EnrollmentConfirmRequest(
                    bindingId = attestOk.bindingId,
                    popPayload = popPayload,
                    signatureBase64Url = Base64Url.encode(forgedPop),
                    authMetadata = ClientAuthMetadata(SecurityBacking.TEE, AuthPolicyUsed.BIOMETRIC_STRONG),
                ),
            )
        assertEquals(VerdictStatus.REJECTED_FRAUD_SIGNAL, confirmResp.verdict.status)
        assertEquals(EnrollmentStatus.PENDING_POP, confirmResp.status)
        assertTrue(confirmResp.verdict.findings.any { it.code == FindingCode.SIGNATURE_INVALID })
    }

    @Test
    fun forgedSoftwareKeySignatureAndWeakBiometricDowngradeAreRejectedByServer() {
        val root = createRootCa(isRkp = true)
        val verifier =
            MaigBindVerifier(
                policy = VerificationPolicy(allowWeakBiometricOptIn = false),
                trustStoreProvider = StaticTrustStoreProvider(listOf(root.cert)),
                revocationStatusProvider = StaticRevocationStatusProvider(),
                clock = fixedClock,
            )
        val (genuineKey, keyId) = enroll(verifier, root, "acct-attack")
        val nonce = verifier.issueTransactionNonce("acct-attack", keyId)
        val payload =
            TransactionPayload(
                keyId = keyId,
                operationType = "PIX_TRANSFER",
                nonce = nonce.nonceBase64Url,
                issuedAt = nonce.issuedAt,
                expiresAt = nonce.expiresAt,
                fields = canonicalFields("amountCents" to canonical(50_000L)),
            )

        // T1: Forged software key from Frida CryptoObject swap
        val rogueKey = generateP256()
        val forgedVerdict =
            verifier.verifyTransaction(
                accountId = "acct-attack",
                signedPayload =
                    SignedPayload(
                        payload = payload,
                        signatureBase64Url = Base64Url.encode(sign(rogueKey, payload.signingInput())),
                        authMetadata = ClientAuthMetadata(SecurityBacking.TEE, AuthPolicyUsed.BIOMETRIC_STRONG),
                    ),
                expectedOperationType = "PIX_TRANSFER",
                expectedFields = payload.fields,
            )
        assertEquals(VerdictStatus.REJECTED_FRAUD_SIGNAL, forgedVerdict.status)
        assertTrue(forgedVerdict.findings.any { it.code == FindingCode.SIGNATURE_INVALID })

        // T8: Weak biometric downgrade
        val nonce2 = verifier.issueTransactionNonce("acct-attack", keyId)
        val payload2 = payload.copy(nonce = nonce2.nonceBase64Url)
        val weakVerdict =
            verifier.verifyTransaction(
                accountId = "acct-attack",
                signedPayload =
                    SignedPayload(
                        payload = payload2,
                        signatureBase64Url = Base64Url.encode(sign(genuineKey, payload2.signingInput())),
                        authMetadata = ClientAuthMetadata(SecurityBacking.TEE, AuthPolicyUsed.BIOMETRIC_WEAK_OPT_IN),
                    ),
                expectedOperationType = "PIX_TRANSFER",
                expectedFields = payload2.fields,
            )
        assertEquals(VerdictStatus.REJECTED_POLICY, weakVerdict.status)
        assertTrue(weakVerdict.findings.any { it.code == FindingCode.DOWNGRADED_AUTH_POLICY_REJECTED })
    }

    @Test
    fun detectsAndRejectsSuspiciousKeyboxFanOut() {
        val factoryRoot = createRootCa(isRkp = false)
        val sharedLeakedBatch = createIntermediate(factoryRoot, BigInteger("99999"))
        val verifier =
            MaigBindVerifier(
                policy =
                    VerificationPolicy(
                        keyboxSuspicionThreshold = 3,
                        rejectOnSuspiciousKeybox = true,
                    ),
                trustStoreProvider = StaticTrustStoreProvider(listOf(factoryRoot.cert)),
                revocationStatusProvider = StaticRevocationStatusProvider(),
                clock = fixedClock,
            )

        repeat(2) { idx ->
            val acct = "acct-$idx"
            val ch = verifier.beginEnrollment(acct)
            val kp = generateP256()
            val leaf =
                createLeaf(
                    rootCert = sharedLeakedBatch.cert,
                    rootPair = sharedLeakedBatch.keyPair,
                    leafPair = kp,
                    challenge = Base64Url.decode(ch.challengeBase64Url),
                    sigAlg = "SHA256withRSA",
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
                                sharedLeakedBatch.cert,
                            ).map { Base64Url.encode(it.encoded) },
                        challengeBase64Url = ch.challengeBase64Url,
                        securityBacking = SecurityBacking.TEE,
                    ),
                )
            assertTrue(resp.verdict.isVerified)
        }

        // 3rd distinct account using the exact same factory intermediate hits threshold
        val ch3 = verifier.beginEnrollment("acct-2")
        val kp3 = generateP256()
        val leaf3 =
            createLeaf(
                rootCert = sharedLeakedBatch.cert,
                rootPair = sharedLeakedBatch.keyPair,
                leafPair = kp3,
                challenge = Base64Url.decode(ch3.challengeBase64Url),
                sigAlg = "SHA256withRSA",
            )
        val resp3 =
            verifier.verifyEnrollmentAttestation(
                EnrollmentRequest(
                    accountId = "acct-2",
                    keyId = computeKeyId(kp3.public.encoded),
                    publicKeySpkiBase64Url = Base64Url.encode(kp3.public.encoded),
                    attestationChainBase64Url =
                        listOf(
                            leaf3,
                            sharedLeakedBatch.cert,
                        ).map { Base64Url.encode(it.encoded) },
                    challengeBase64Url = ch3.challengeBase64Url,
                    securityBacking = SecurityBacking.TEE,
                ),
            )
        assertFalse(resp3.verdict.isVerified)
        assertTrue(resp3.verdict.findings.any { it.code == FindingCode.SUSPICIOUS_KEYBOX_FANOUT })
    }

    private fun enroll(
        verifier: MaigBindVerifier,
        root: Ca,
        accountId: String,
    ): Pair<KeyPair, String> {
        val ch = verifier.beginEnrollment(accountId)
        val kp = generateP256()
        val keyId = computeKeyId(kp.public.encoded)
        val leaf = createLeaf(root.cert, root.keyPair, kp, Base64Url.decode(ch.challengeBase64Url))
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
                    signatureBase64Url = Base64Url.encode(sign(kp, pop.signingInput())),
                    authMetadata = ClientAuthMetadata(SecurityBacking.TEE, AuthPolicyUsed.BIOMETRIC_STRONG),
                ),
            )
        assertEquals(EnrollmentStatus.ACTIVE, confirm.status)
        return kp to keyId
    }

    private data class Ca(
        val cert: X509Certificate,
        val keyPair: KeyPair,
    )

    private fun generateP256(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun sign(
        kp: KeyPair,
        bytes: ByteArray,
    ): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private)
            update(bytes)
            sign()
        }

    private fun createRootCa(isRkp: Boolean): Ca {
        val kp =
            if (isRkp) {
                KeyPairGenerator
                    .getInstance(
                        "EC",
                    ).apply { initialize(ECGenParameterSpec("secp384r1")) }
                    .generateKeyPair()
            } else {
                KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            }
        val alg = if (isRkp) "SHA384withECDSA" else "SHA256withRSA"
        val dn = X500Name("CN=${if (isRkp) "Key Attestation CA1" else "Factory Root"}, O=Google LLC, C=US")
        val builder =
            JcaX509v3CertificateBuilder(
                dn,
                BigInteger.ONE,
                Date.from(fixedNow.minus(Duration.ofDays(10))),
                Date.from(fixedNow.plus(Duration.ofDays(365))),
                dn,
                kp.public,
            ).apply {
                addExtension(Extension.basicConstraints, true, BasicConstraints(true))
                addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
            }
        val cert =
            JcaX509CertificateConverter().setProvider("BC").getCertificate(
                builder.build(JcaContentSignerBuilder(alg).setProvider("BC").build(kp.private)),
            )
        return Ca(cert, kp)
    }

    private fun createIntermediate(
        parent: Ca,
        serial: BigInteger,
    ): Ca {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val builder =
            JcaX509v3CertificateBuilder(
                X500Name.getInstance(parent.cert.subjectX500Principal.encoded),
                serial,
                Date.from(fixedNow.minus(Duration.ofDays(5))),
                Date.from(fixedNow.plus(Duration.ofDays(365))),
                X500Name("CN=Batch CA $serial, O=OEM, C=US"),
                kp.public,
            ).apply {
                val ext = JcaX509ExtensionUtils()
                addExtension(Extension.basicConstraints, true, BasicConstraints(true))
                addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
                addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(parent.cert))
            }
        val cert =
            JcaX509CertificateConverter().setProvider("BC").getCertificate(
                builder.build(JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(parent.keyPair.private)),
            )
        return Ca(cert, kp)
    }

    private fun createLeaf(
        rootCert: X509Certificate,
        rootPair: KeyPair,
        leafPair: KeyPair,
        challenge: ByteArray,
        sigAlg: String = "SHA384withECDSA",
        appPkg: String = officialApp.packageName,
        appDigest: ByteArray = officialApp.signingCertSha256Digests.first(),
    ): X509Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                X500Name.getInstance(rootCert.subjectX500Principal.encoded),
                BigInteger.TEN,
                Date.from(fixedNow.minus(Duration.ofHours(1))),
                Date.from(fixedNow.plus(Duration.ofDays(30))),
                X500Name("CN=Android Keystore Key"),
                leafPair.public,
            )
        val swVec =
            ASN1EncodableVector().apply {
                val pkgSeq = DERSequence(arrayOf(DEROctetString(appPkg.encodeToByteArray()), ASN1Integer(1L)))
                val appIdSeq = DERSequence(arrayOf(DERSet(pkgSeq), DERSet(DEROctetString(appDigest))))
                add(DERTaggedObject(true, 709, DEROctetString(appIdSeq.encoded)))
            }
        val hwVec =
            ASN1EncodableVector().apply {
                add(DERTaggedObject(true, 1, DERSet(ASN1Integer(2L))))
                add(DERTaggedObject(true, 2, ASN1Integer(3L)))
                add(DERTaggedObject(true, 10, ASN1Integer(1L)))
                add(DERTaggedObject(true, 504, ASN1Integer(2L)))
                add(DERTaggedObject(true, 505, ASN1Integer(0L)))
                val rotSeq =
                    DERSequence(
                        arrayOf(
                            DEROctetString(ByteArray(32) { 1 }),
                            ASN1Boolean.getInstance(true),
                            ASN1Enumerated(0),
                            DEROctetString(ByteArray(32) { 2 }),
                        ),
                    )
                add(DERTaggedObject(true, 704, rotSeq))
            }
        val keyDesc =
            DERSequence(
                arrayOf(
                    ASN1Integer(200L),
                    ASN1Enumerated(1),
                    ASN1Integer(200L),
                    ASN1Enumerated(1),
                    DEROctetString(challenge),
                    DEROctetString(ByteArray(0)),
                    DERSequence(swVec),
                    DERSequence(hwVec),
                ),
            )
        builder.addExtension(ASN1ObjectIdentifier(KEY_ATTESTATION_OID), false, keyDesc)
        val signer = JcaContentSignerBuilder(sigAlg).setProvider("BC").build(rootPair.private)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
    }
}
