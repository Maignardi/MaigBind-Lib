package io.github.maignardi.maigbind.verifier

import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.SignedPayload
import io.github.maignardi.maigbind.core.TransactionPayload
import io.github.maignardi.maigbind.core.canonical
import io.github.maignardi.maigbind.core.canonicalFields
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.Instant
import java.util.Date

internal data class TestCaBundle(
    val cert: X509Certificate,
    val keyPair: KeyPair,
)

internal object TestPkiFixture {
    fun generateP256KeyPair(): KeyPair =
        KeyPairGenerator
            .getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

    fun ecdsaSign(
        privateKey: PrivateKey,
        data: ByteArray,
    ): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }

    fun signSampleTx(
        keyPair: KeyPair,
        keyId: String,
        nonce: String,
        issuedAt: Long,
        expiresAt: Long,
    ): SignedPayload {
        val payload =
            TransactionPayload(
                keyId = keyId,
                operationType = "PIX_TRANSFER",
                nonce = nonce,
                issuedAt = issuedAt,
                expiresAt = expiresAt,
                fields =
                    canonicalFields(
                        "amountCents" to canonical(150_000L),
                        "currency" to canonical("BRL"),
                        "recipient" to canonical("alice@bank.example"),
                    ),
            )
        return SignedPayload(
            payload = payload,
            signatureBase64Url = Base64Url.encode(ecdsaSign(keyPair.private, payload.signingInput())),
        )
    }

    fun createRootCa(
        now: Instant,
        isRkpP384: Boolean,
        cn: String = if (isRkpP384) "Key Attestation CA1" else "Android Hardware Attestation Root",
    ): TestCaBundle {
        val keyPair =
            if (isRkpP384) {
                KeyPairGenerator
                    .getInstance(
                        "EC",
                    ).apply { initialize(ECGenParameterSpec("secp384r1")) }
                    .generateKeyPair()
            } else {
                KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            }
        val sigAlg = if (isRkpP384) "SHA384withECDSA" else "SHA256withRSA"
        val subject = X500Name("CN=$cn, OU=Android, O=Google LLC, C=US")
        val builder =
            JcaX509v3CertificateBuilder(
                subject,
                BigInteger.ONE,
                Date.from(now.minus(Duration.ofDays(365))),
                Date.from(now.plus(Duration.ofDays(3650))),
                subject,
                keyPair.public,
            )
        val extUtils = JcaX509ExtensionUtils()
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.public))
        val signer = JcaContentSignerBuilder(sigAlg).setProvider("BC").build(keyPair.private)
        val cert = JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
        return TestCaBundle(cert, keyPair)
    }

    fun createIntermediateCa(
        now: Instant,
        parent: TestCaBundle,
        isP384: Boolean,
        serial: BigInteger,
    ): TestCaBundle {
        val keyPair =
            if (isP384) {
                KeyPairGenerator
                    .getInstance(
                        "EC",
                    ).apply { initialize(ECGenParameterSpec("secp384r1")) }
                    .generateKeyPair()
            } else {
                KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            }
        val sigAlg = if (parent.keyPair.public.algorithm == "EC") "SHA384withECDSA" else "SHA256withRSA"
        val subject = X500Name("CN=Batch Intermediate $serial, O=Google LLC, C=US")
        val builder =
            JcaX509v3CertificateBuilder(
                X500Name.getInstance(parent.cert.subjectX500Principal.encoded),
                serial,
                Date.from(now.minus(Duration.ofDays(30))),
                Date.from(now.plus(Duration.ofDays(365))),
                subject,
                keyPair.public,
            )
        val extUtils = JcaX509ExtensionUtils()
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.public))
        builder.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            extUtils.createAuthorityKeyIdentifier(parent.cert),
        )
        val signer = JcaContentSignerBuilder(sigAlg).setProvider("BC").build(parent.keyPair.private)
        val cert = JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
        return TestCaBundle(cert, keyPair)
    }

    fun createAttestedLeaf(
        now: Instant,
        issuerCert: X509Certificate,
        issuerKey: PrivateKey,
        issuerSigAlg: String,
        leafKeyPair: KeyPair,
        serial: BigInteger,
        challenge: ByteArray,
        appPkg: String,
        appSigDigest: ByteArray,
        attestationSecLevel: Int = 1,
        keymasterSecLevel: Int = 1,
        deviceLocked: Boolean = true,
        verifiedBootState: Int = 0,
        noAuthRequired: Boolean = false,
        userAuthType: Long? = 2L,
        authTimeout: Long? = 0L,
        osPatchLevel: Int = 202610,
        notBefore: Date = Date.from(now.minus(Duration.ofHours(1))),
        notAfter: Date = Date.from(now.plus(Duration.ofDays(30))),
    ): X509Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                X500Name.getInstance(issuerCert.subjectX500Principal.encoded),
                serial,
                notBefore,
                notAfter,
                X500Name("CN=Android Keystore Key"),
                leafKeyPair.public,
            )
        val extUtils = JcaX509ExtensionUtils()
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
        builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerCert))

        val swVec =
            ASN1EncodableVector().apply {
                val pkgSeq = DERSequence(arrayOf(DEROctetString(appPkg.encodeToByteArray()), ASN1Integer(1L)))
                val appIdSeq = DERSequence(arrayOf(DERSet(pkgSeq), DERSet(DEROctetString(appSigDigest))))
                add(DERTaggedObject(true, 709, DEROctetString(appIdSeq.encoded)))
            }
        val hwVec =
            ASN1EncodableVector().apply {
                add(DERTaggedObject(true, 1, DERSet(ASN1Integer(2L))))
                add(DERTaggedObject(true, 2, ASN1Integer(3L)))
                add(DERTaggedObject(true, 3, ASN1Integer(256L)))
                add(DERTaggedObject(true, 10, ASN1Integer(1L)))
                if (noAuthRequired) add(DERTaggedObject(true, 503, DERNull.INSTANCE))
                if (userAuthType != null) add(DERTaggedObject(true, 504, ASN1Integer(userAuthType)))
                if (authTimeout != null) add(DERTaggedObject(true, 505, ASN1Integer(authTimeout)))
                val rotSeq =
                    DERSequence(
                        arrayOf(
                            DEROctetString(ByteArray(32) { 0x11 }),
                            ASN1Boolean.getInstance(deviceLocked),
                            ASN1Enumerated(verifiedBootState),
                            DEROctetString(ByteArray(32) { 0x22 }),
                        ),
                    )
                add(DERTaggedObject(true, 704, rotSeq))
                add(DERTaggedObject(true, 706, ASN1Integer(osPatchLevel.toLong())))
            }
        val keyDesc =
            DERSequence(
                arrayOf(
                    ASN1Integer(200L),
                    ASN1Enumerated(attestationSecLevel),
                    ASN1Integer(200L),
                    ASN1Enumerated(keymasterSecLevel),
                    DEROctetString(challenge),
                    DEROctetString(ByteArray(0)),
                    DERSequence(swVec),
                    DERSequence(hwVec),
                ),
            )
        builder.addExtension(ASN1ObjectIdentifier(KEY_ATTESTATION_OID), false, keyDesc)
        val signer = JcaContentSignerBuilder(issuerSigAlg).setProvider("BC").build(issuerKey)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
    }
}
