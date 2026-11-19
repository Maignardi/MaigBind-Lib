package io.github.maignardi.maigbind.core

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CoreProtocolTest {
    @Test
    fun sha256MatchesFips180_4Vectors() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            Sha256.digest(ByteArray(0)).toHexString(),
        )
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Sha256.digest("abc".encodeToByteArray()).toHexString(),
        )
        assertEquals(
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            Sha256.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".encodeToByteArray()).toHexString(),
        )
    }

    @Test
    fun base64UrlRoundTripsAndRejectsNonCanonicalInputs() {
        val inputs =
            listOf(
                ByteArray(0),
                byteArrayOf(0x00),
                byteArrayOf(0x00, 0x01),
                byteArrayOf(0x00, 0x01, 0x02),
                byteArrayOf(0xFF.toByte(), 0xEE.toByte(), 0xDD.toByte(), 0xCC.toByte()),
                "MaigBind-RFC4648-Vector".encodeToByteArray(),
            )
        for (raw in inputs) {
            val encoded = Base64Url.encode(raw)
            assertTrue('=' !in encoded)
            assertContentEquals(raw, Base64Url.decode(encoded))
        }
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("ab=") }
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("a") }
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("ab+c") }
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("ab/c") }
    }

    @Test
    fun deterministicCborEnforcesRfc8949KeyOrderingByEncodedLengthThenLex() {
        // Key "z" encodes as 61 7a (2 bytes); key "aa" encodes as 62 61 61 (3 bytes).
        // Under RFC 8949 §4.2.1 canonical ordering, "z" MUST come BEFORE "aa"!
        val value =
            CanonicalValue.MapValue(
                mapOf(
                    "aa" to canonical(1),
                    "z" to canonical(2),
                    "a" to canonical(3),
                ),
            )
        val encoded = DeterministicCbor.encode(value)
        // Expected: a3 (map of 3) | 61 61 03 ("a": 3) | 61 7a 02 ("z": 2) | 62 61 61 01 ("aa": 1)
        assertEquals("a3616103617a0262616101", encoded.toHexString())
        assertEquals(value, DeterministicCbor.decode(encoded))
    }

    @Test
    fun deterministicCborEncodesNegativeAndLargeIntegers() {
        val cases =
            listOf(
                0L to "00",
                23L to "17",
                24L to "1818",
                255L to "18ff",
                256L to "190100",
                65536L to "1a00010000",
                4294967296L to "1b0000000100000000",
                -1L to "20",
                -24L to "37",
                -25L to "3818",
                -1000L to "3903e7",
                Long.MIN_VALUE to "3b7fffffffffffffff",
                Long.MAX_VALUE to "1b7fffffffffffffff",
            )
        for ((num, expectedHex) in cases) {
            val encoded = DeterministicCbor.encode(canonical(num))
            assertEquals(expectedHex, encoded.toHexString())
            assertEquals(canonical(num), DeterministicCbor.decode(encoded))
        }
    }

    @Test
    fun deterministicCborRejectsNonCanonicalEncodings() {
        // Non-minimal integer: 0x18 0x05 encodes 5 using 2 bytes instead of 0x05
        assertFailsWith<IllegalArgumentException> {
            DeterministicCbor.decode(byteArrayOf(0x18, 0x05))
        }
        // Indefinite-length map: 0xBF 0xFF
        assertFailsWith<IllegalArgumentException> {
            DeterministicCbor.decode(byteArrayOf(0xBF.toByte(), 0xFF.toByte()))
        }
        // Out-of-order map keys: {"z": 2, "a": 1}
        assertFailsWith<IllegalArgumentException> {
            DeterministicCbor.decode(
                byteArrayOf(
                    0xA2.toByte(),
                    0x61,
                    0x7A,
                    0x02,
                    0x61,
                    0x61,
                    0x01,
                ),
            )
        }
        // Duplicate map keys: {"a": 1, "a": 2}
        assertFailsWith<IllegalArgumentException> {
            DeterministicCbor.decode(
                byteArrayOf(
                    0xA2.toByte(),
                    0x61,
                    0x61,
                    0x01,
                    0x61,
                    0x61,
                    0x02,
                ),
            )
        }
        // Trailing bytes
        assertFailsWith<IllegalArgumentException> {
            DeterministicCbor.decode(byteArrayOf(0x01, 0x02))
        }
    }

    @Test
    fun transactionPayloadCanonicalVectorAndDomainSeparationAreDeterministic() {
        val payloadA =
            TransactionPayload(
                protocolVersion = 1,
                keyId = "test-key-id-01",
                operationType = "PIX_TRANSFER",
                nonce = "nonce-123456",
                issuedAt = 1_770_000_000_000L,
                expiresAt = 1_770_000_090_000L,
                fields =
                    canonicalFields(
                        "currency" to canonical("BRL"),
                        "amountCents" to canonical(150_000L),
                        "recipient" to canonical("bob@bank.example"),
                    ),
            )
        // Construct identical payload with different map insertion order
        val payloadB =
            TransactionPayload(
                protocolVersion = 1,
                keyId = "test-key-id-01",
                operationType = "PIX_TRANSFER",
                nonce = "nonce-123456",
                issuedAt = 1_770_000_000_000L,
                expiresAt = 1_770_000_090_000L,
                fields =
                    canonicalFields(
                        "recipient" to canonical("bob@bank.example"),
                        "amountCents" to canonical(150_000L),
                        "currency" to canonical("BRL"),
                    ),
            )

        val cborA = payloadA.toCanonicalCborBytes()
        val cborB = payloadB.toCanonicalCborBytes()
        assertContentEquals(cborA, cborB)
        assertEquals(payloadA, TransactionPayload.fromCanonicalCborBytes(cborA))

        val txInput = payloadA.signingInput()
        val expectedPrefix = "MaigBind/v1/tx\u0000".encodeToByteArray()
        assertContentEquals(expectedPrefix, txInput.copyOfRange(0, expectedPrefix.size))
        assertContentEquals(cborA, txInput.copyOfRange(expectedPrefix.size, txInput.size))

        // Pin exact SHA-256 of canonical vector so JVM, Android, and iOS verify identical bytes
        assertEquals(
            "3793dd4a93820534670754938bedbacf4b9ede48ee77bd2a123f94803e755733",
            Sha256.digest(txInput).toHexString(),
        )
    }

    @Test
    fun enrollmentPopUsesDistinctDomainTag() {
        val pop =
            EnrollmentPoPPayload(
                protocolVersion = 1,
                keyId = "test-key-id-01",
                accountId = "acct-42",
                challenge = "pop-challenge-xyz",
                issuedAt = 1_770_000_000_000L,
                expiresAt = 1_770_000_060_000L,
            )
        val input = pop.signingInput()
        val expectedPrefix = "MaigBind/v1/enroll-pop\u0000".encodeToByteArray()
        assertContentEquals(expectedPrefix, input.copyOfRange(0, expectedPrefix.size))
        assertContentEquals(pop.toCanonicalCborBytes(), input.copyOfRange(expectedPrefix.size, input.size))
    }

    @Test
    fun deterministicCborHandlesNestedListsMapsBooleansBytesAndUtf8Keys() {
        val nested =
            CanonicalValue.MapValue(
                mapOf(
                    "zz" to canonical(true),
                    "é" to
                        CanonicalValue.ListValue(
                            listOf(
                                canonical(false),
                                canonical(byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())),
                                CanonicalValue.MapValue(mapOf("inner" to canonical(-42L))),
                            ),
                        ),
                    "a" to canonical("text"),
                ),
            )
        val encoded = DeterministicCbor.encode(nested)
        val decoded = DeterministicCbor.decode(encoded) as CanonicalValue.MapValue
        assertTrue(nested.contentEquals(decoded))
        // "a" (1 byte) < "zz" (2 bytes) <= "é" (2 UTF-8 bytes: 0xc3 0xa9 > 0x7a 0x7a)
        assertEquals(listOf("a", "zz", "é"), decoded.entries.keys.toList())
    }
}
