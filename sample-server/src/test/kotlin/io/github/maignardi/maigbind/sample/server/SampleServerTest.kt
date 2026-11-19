package io.github.maignardi.maigbind.sample.server

import io.github.maignardi.maigbind.core.AuthPolicyUsed
import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.ClientAuthMetadata
import io.github.maignardi.maigbind.core.EnrollmentAttestResponse
import io.github.maignardi.maigbind.core.EnrollmentConfirmRequest
import io.github.maignardi.maigbind.core.EnrollmentConfirmResponse
import io.github.maignardi.maigbind.core.EnrollmentPoPPayload
import io.github.maignardi.maigbind.core.EnrollmentRequest
import io.github.maignardi.maigbind.core.EnrollmentStatus
import io.github.maignardi.maigbind.core.FindingCode
import io.github.maignardi.maigbind.core.SecurityBacking
import io.github.maignardi.maigbind.core.SignedPayload
import io.github.maignardi.maigbind.core.TransactionPayload
import io.github.maignardi.maigbind.core.canonical
import io.github.maignardi.maigbind.core.canonicalFields
import io.github.maignardi.maigbind.core.computeKeyId
import io.github.maignardi.maigbind.verifier.KEY_ATTESTATION_OID
import io.github.maignardi.maigbind.verifier.MaigBindVerifier
import io.github.maignardi.maigbind.verifier.StaticRevocationStatusProvider
import io.github.maignardi.maigbind.verifier.StaticTrustStoreProvider
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
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

class SampleServerTest {
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }
    private val fixedNow = Instant.parse("2026-11-18T12:00:00Z")
    private val fixedClock = Clock.fixed(fixedNow, ZoneOffset.UTC)

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Test
    fun endToEndHttpEnrollmentAndTransactionFlowAndAttackRejections() =
        testApplication {
            val (rootCert, rootKp) = createRkpRootCa()
            val verifier =
                MaigBindVerifier(
                    trustStoreProvider = StaticTrustStoreProvider(listOf(rootCert)),
                    revocationStatusProvider = StaticRevocationStatusProvider(),
                    clock = fixedClock,
                )
            application { configureSampleServer(verifier) }

            val noMfaResp =
                client.post("/enroll/begin") {
                    contentType(ContentType.Application.Json)
                    setBody(json.encodeToString(BeginEnrollHttpRequest("acct-99", "wrong-token")))
                }
            assertEquals(HttpStatusCode.Unauthorized, noMfaResp.status)

            val (devKey, keyId) = enrollViaHttp(client, rootCert, rootKp)

            val txChResp =
                client.post("/tx/challenge") {
                    contentType(ContentType.Application.Json)
                    setBody(json.encodeToString(TxChallengeHttpRequest("acct-99", keyId)))
                }
            assertEquals(HttpStatusCode.OK, txChResp.status)
            val txCh = json.decodeFromString<TxChallengeHttpResponse>(txChResp.bodyAsText())

            val execReq = buildSignedTransferRequest(devKey, keyId, txCh)
            val execResp =
                client.post("/tx/execute") {
                    contentType(ContentType.Application.Json)
                    setBody(json.encodeToString(execReq))
                }
            assertEquals(HttpStatusCode.OK, execResp.status)
            assertTrue(json.decodeFromString<ExecuteTransferHttpResponse>(execResp.bodyAsText()).executed)

            val replayResp =
                client.post("/tx/execute") {
                    contentType(ContentType.Application.Json)
                    setBody(json.encodeToString(execReq))
                }
            assertEquals(HttpStatusCode.Forbidden, replayResp.status)
            val replayBody = json.decodeFromString<ExecuteTransferHttpResponse>(replayResp.bodyAsText())
            assertFalse(replayBody.executed)
            assertTrue(replayBody.verdict.findings.any { it.code == FindingCode.NONCE_REPLAYED_OR_UNKNOWN })
        }

    private fun createRkpRootCa(): Pair<X509Certificate, KeyPair> {
        val rootKp =
            KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        val rootName = X500Name("CN=Key Attestation CA1, O=Google LLC, C=US")
        val rootBuilder =
            JcaX509v3CertificateBuilder(
                rootName,
                BigInteger.ONE,
                Date.from(fixedNow.minus(Duration.ofDays(30))),
                Date.from(fixedNow.plus(Duration.ofDays(365))),
                rootName,
                rootKp.public,
            ).apply {
                addExtension(Extension.basicConstraints, true, BasicConstraints(true))
                addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
            }
        val rootCert =
            JcaX509CertificateConverter().setProvider("BC").getCertificate(
                rootBuilder.build(JcaContentSignerBuilder("SHA384withECDSA").setProvider("BC").build(rootKp.private)),
            )
        return rootCert to rootKp
    }

    private suspend fun enrollViaHttp(
        client: io.ktor.client.HttpClient,
        rootCert: X509Certificate,
        rootKp: KeyPair,
    ): Pair<KeyPair, String> {
        val beginResp =
            client.post("/enroll/begin") {
                contentType(ContentType.Application.Json)
                setBody(json.encodeToString(BeginEnrollHttpRequest("acct-99", DEMO_VALID_STEP_UP_TOKEN)))
            }
        assertEquals(HttpStatusCode.OK, beginResp.status)
        val beginBody = json.decodeFromString<BeginEnrollHttpResponse>(beginResp.bodyAsText())

        val devKey =
            KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val keyId = computeKeyId(devKey.public.encoded)
        val leafCert = createLeaf(rootCert, rootKp, devKey, Base64Url.decode(beginBody.challengeBase64Url))

        val attestResp =
            client.post("/enroll/attest") {
                contentType(ContentType.Application.Json)
                setBody(
                    json.encodeToString(
                        EnrollmentRequest(
                            accountId = "acct-99",
                            keyId = keyId,
                            publicKeySpkiBase64Url = Base64Url.encode(devKey.public.encoded),
                            attestationChainBase64Url = listOf(Base64Url.encode(leafCert.encoded)),
                            challengeBase64Url = beginBody.challengeBase64Url,
                            securityBacking = SecurityBacking.STRONGBOX,
                        ),
                    ),
                )
            }
        assertEquals(HttpStatusCode.OK, attestResp.status)
        val attestBody = json.decodeFromString<EnrollmentAttestResponse>(attestResp.bodyAsText())
        assertEquals(EnrollmentStatus.PENDING_POP, attestBody.status)

        val popPayload =
            EnrollmentPoPPayload(
                keyId = keyId,
                accountId = "acct-99",
                challenge = attestBody.popChallengeBase64Url,
                issuedAt = fixedNow.toEpochMilli(),
                expiresAt = attestBody.popExpiresAt,
            )
        val popSig = ecdsaSign(devKey, popPayload.signingInput())
        val confirmResp =
            client.post("/enroll/confirm") {
                contentType(ContentType.Application.Json)
                setBody(
                    json.encodeToString(
                        EnrollmentConfirmRequest(
                            bindingId = attestBody.bindingId,
                            popPayload = popPayload,
                            signatureBase64Url = Base64Url.encode(popSig),
                            authMetadata =
                                ClientAuthMetadata(
                                    SecurityBacking.STRONGBOX,
                                    AuthPolicyUsed.BIOMETRIC_STRONG,
                                ),
                        ),
                    ),
                )
            }
        assertEquals(HttpStatusCode.OK, confirmResp.status)
        val confirmBody = json.decodeFromString<EnrollmentConfirmResponse>(confirmResp.bodyAsText())
        assertEquals(EnrollmentStatus.ACTIVE, confirmBody.status)
        return devKey to keyId
    }

    private fun buildSignedTransferRequest(
        devKey: KeyPair,
        keyId: String,
        txCh: TxChallengeHttpResponse,
    ): ExecuteTransferHttpRequest {
        val txPayload =
            TransactionPayload(
                keyId = keyId,
                operationType = "PIX_TRANSFER",
                nonce = txCh.nonceBase64Url,
                issuedAt = txCh.issuedAt,
                expiresAt = txCh.expiresAt,
                fields =
                    canonicalFields(
                        "amountCents" to canonical(250_00L),
                        "currency" to canonical("BRL"),
                        "recipient" to canonical("bob@pix.br"),
                    ),
            )
        val signedPayload =
            SignedPayload(
                payload = txPayload,
                signatureBase64Url = Base64Url.encode(ecdsaSign(devKey, txPayload.signingInput())),
                authMetadata = ClientAuthMetadata(SecurityBacking.STRONGBOX, AuthPolicyUsed.BIOMETRIC_STRONG),
            )
        return ExecuteTransferHttpRequest(
            accountId = "acct-99",
            recipient = "bob@pix.br",
            amountCents = 250_00L,
            currency = "BRL",
            signedPayload = signedPayload,
        )
    }

    private fun ecdsaSign(
        kp: KeyPair,
        bytes: ByteArray,
    ): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private)
            update(bytes)
            sign()
        }

    private fun createLeaf(
        rootCert: X509Certificate,
        rootKp: KeyPair,
        devKey: KeyPair,
        challenge: ByteArray,
    ): X509Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                X500Name.getInstance(rootCert.subjectX500Principal.encoded),
                BigInteger.TEN,
                Date.from(fixedNow.minus(Duration.ofHours(1))),
                Date.from(fixedNow.plus(Duration.ofDays(30))),
                X500Name("CN=Android Keystore Key"),
                devKey.public,
            )
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
                    ASN1Enumerated(2),
                    ASN1Integer(200L),
                    ASN1Enumerated(2),
                    DEROctetString(challenge),
                    DEROctetString(ByteArray(0)),
                    DERSequence(),
                    DERSequence(hwVec),
                ),
            )
        builder.addExtension(ASN1ObjectIdentifier(KEY_ATTESTATION_OID), false, keyDesc)
        val signer = JcaContentSignerBuilder("SHA384withECDSA").setProvider("BC").build(rootKp.private)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
    }
}
