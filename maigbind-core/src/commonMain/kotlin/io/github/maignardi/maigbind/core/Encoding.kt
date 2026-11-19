package io.github.maignardi.maigbind.core

/**
 * Unpadded RFC 4648 Section 5 Base64url encoder and strict decoder.
 */
public object Base64Url {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    private val DECODE_TABLE =
        IntArray(128) { -1 }.apply {
            for (i in ALPHABET.indices) {
                this[ALPHABET[i].code] = i
            }
        }

    /**
     * Encodes [bytes] using URL-safe Base64 without `=` padding.
     */
    public fun encode(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val out = StringBuilder((bytes.size * 4 + 2) / 3)
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val hasB1 = i + 1 < bytes.size
            val hasB2 = i + 2 < bytes.size
            val b1 = if (hasB1) bytes[i + 1].toInt() and 0xFF else 0
            val b2 = if (hasB2) bytes[i + 2].toInt() and 0xFF else 0

            val triple = (b0 shl 16) or (b1 shl 8) or b2
            out.append(ALPHABET[(triple ushr 18) and 0x3F])
            out.append(ALPHABET[(triple ushr 12) and 0x3F])
            if (hasB1) out.append(ALPHABET[(triple ushr 6) and 0x3F])
            if (hasB2) out.append(ALPHABET[triple and 0x3F])
            i += 3
        }
        return out.toString()
    }

    /**
     * Decodes an unpadded Base64url string.
     *
     * @throws IllegalArgumentException if [encoded] contains padding, whitespace, invalid
     * characters, or a trailing 1-character remainder.
     */
    public fun decode(encoded: String): ByteArray {
        if (encoded.isEmpty()) return ByteArray(0)
        val remainder = encoded.length % 4
        require(remainder != 1) { "Invalid Base64url length: ${encoded.length}" }

        val outLen =
            (encoded.length / 4) * 3 +
                when (remainder) {
                    2 -> 1
                    3 -> 2
                    else -> 0
                }
        val out = ByteArray(outLen)
        var outIdx = 0
        var i = 0
        while (i + 3 < encoded.length) {
            val c0 = decodeChar(encoded[i])
            val c1 = decodeChar(encoded[i + 1])
            val c2 = decodeChar(encoded[i + 2])
            val c3 = decodeChar(encoded[i + 3])
            val triple = (c0 shl 18) or (c1 shl 12) or (c2 shl 6) or c3
            out[outIdx++] = ((triple ushr 16) and 0xFF).toByte()
            out[outIdx++] = ((triple ushr 8) and 0xFF).toByte()
            out[outIdx++] = (triple and 0xFF).toByte()
            i += 4
        }

        if (remainder == 2) {
            val c0 = decodeChar(encoded[i])
            val c1 = decodeChar(encoded[i + 1])
            require((c1 and 0x0F) == 0) { "Non-canonical Base64url trailing bits" }
            out[outIdx] = ((c0 shl 2) or (c1 ushr 4)).toByte()
        } else if (remainder == 3) {
            val c0 = decodeChar(encoded[i])
            val c1 = decodeChar(encoded[i + 1])
            val c2 = decodeChar(encoded[i + 2])
            require((c2 and 0x03) == 0) { "Non-canonical Base64url trailing bits" }
            out[outIdx++] = ((c0 shl 2) or (c1 ushr 4)).toByte()
            out[outIdx] = (((c1 and 0x0F) shl 4) or (c2 ushr 2)).toByte()
        }
        return out
    }

    private fun decodeChar(ch: Char): Int {
        val code = ch.code
        if (code >= 128) throw IllegalArgumentException("Invalid Base64url character: '$ch'")
        val value = DECODE_TABLE[code]
        if (value < 0) throw IllegalArgumentException("Invalid Base64url character: '$ch'")
        return value
    }
}

/**
 * Pure Kotlin FIPS 180-4 SHA-256 implementation shared identically across all KMP targets.
 */
public object Sha256 {
    private val K =
        intArrayOf(
            0x428a2f98,
            0x71374491,
            0xb5c0fbcf.toInt(),
            0xe9b5dba5.toInt(),
            0x3956c25b,
            0x59f111f1,
            0x923f82a4.toInt(),
            0xab1c5ed5.toInt(),
            0xd807aa98.toInt(),
            0x12835b01,
            0x243185be,
            0x550c7dc3,
            0x72be5d74,
            0x80deb1fe.toInt(),
            0x9bdc06a7.toInt(),
            0xc19bf174.toInt(),
            0xe49b69c1.toInt(),
            0xefbe4786.toInt(),
            0x0fc19dc6,
            0x240ca1cc,
            0x2de92c6f,
            0x4a7484aa,
            0x5cb0a9dc,
            0x76f988da,
            0x983e5152.toInt(),
            0xa831c66d.toInt(),
            0xb00327c8.toInt(),
            0xbf597fc7.toInt(),
            0xc6e00bf3.toInt(),
            0xd5a79147.toInt(),
            0x06ca6351,
            0x14292967,
            0x27b70a85,
            0x2e1b2138,
            0x4d2c6dfc,
            0x53380d13,
            0x650a7354,
            0x766a0abb,
            0x81c2c92e.toInt(),
            0x92722c85.toInt(),
            0xa2bfe8a1.toInt(),
            0xa81a664b.toInt(),
            0xc24b8b70.toInt(),
            0xc76c51a3.toInt(),
            0xd192e819.toInt(),
            0xd6990624.toInt(),
            0xf40e3585.toInt(),
            0x106aa070,
            0x19a4c116,
            0x1e376c08,
            0x2748774c,
            0x34b0bcb5,
            0x391c0cb3,
            0x4ed8aa4a,
            0x5b9cca4f,
            0x682e6ff3,
            0x748f82ee,
            0x78a5636f,
            0x84c87814.toInt(),
            0x8cc70208.toInt(),
            0x90befffa.toInt(),
            0xa4506ceb.toInt(),
            0xbef9a3f7.toInt(),
            0xc67178f2.toInt(),
        )

    private val INITIAL_H =
        intArrayOf(
            0x6a09e667,
            0xbb67ae85.toInt(),
            0x3c6ef372,
            0xa54ff53a.toInt(),
            0x510e527f,
            0x9b05688c.toInt(),
            0x1f83d9ab,
            0x5be0cd19,
        )

    /**
     * Computes the 32-byte SHA-256 digest of [data].
     */
    public fun digest(data: ByteArray): ByteArray {
        val bitLen = data.size.toLong() * 8L
        val paddedLen = ((data.size + 9 + 63) / 64) * 64
        val padded = ByteArray(paddedLen)
        data.copyInto(padded)
        padded[data.size] = 0x80.toByte()
        for (i in 0 until 8) {
            padded[paddedLen - 1 - i] = ((bitLen ushr (i * 8)) and 0xFF).toByte()
        }

        val h = INITIAL_H.copyOf()
        val w = IntArray(64)

        var offset = 0
        while (offset < paddedLen) {
            for (i in 0 until 16) {
                val base = offset + i * 4
                w[i] = ((padded[base].toInt() and 0xFF) shl 24) or
                    ((padded[base + 1].toInt() and 0xFF) shl 16) or
                    ((padded[base + 2].toInt() and 0xFF) shl 8) or
                    (padded[base + 3].toInt() and 0xFF)
            }
            for (i in 16 until 64) {
                val s0 = w[i - 15].rotateRight(7) xor w[i - 15].rotateRight(18) xor (w[i - 15] ushr 3)
                val s1 = w[i - 2].rotateRight(17) xor w[i - 2].rotateRight(19) xor (w[i - 2] ushr 10)
                w[i] = w[i - 16] + s0 + w[i - 7] + s1
            }

            var a = h[0]
            var b = h[1]
            var c = h[2]
            var d = h[3]
            var e = h[4]
            var f = h[5]
            var g = h[6]
            var hh = h[7]

            for (i in 0 until 64) {
                val s1 = e.rotateRight(6) xor e.rotateRight(11) xor e.rotateRight(25)
                val ch = (e and f) xor (e.inv() and g)
                val temp1 = hh + s1 + ch + K[i] + w[i]
                val s0 = a.rotateRight(2) xor a.rotateRight(13) xor a.rotateRight(22)
                val maj = (a and b) xor (a and c) xor (b and c)
                val temp2 = s0 + maj

                hh = g
                g = f
                f = e
                e = d + temp1
                d = c
                c = b
                b = a
                a = temp1 + temp2
            }

            h[0] += a
            h[1] += b
            h[2] += c
            h[3] += d
            h[4] += e
            h[5] += f
            h[6] += g
            h[7] += hh
            offset += 64
        }

        val out = ByteArray(32)
        for (i in 0 until 8) {
            out[i * 4] = ((h[i] ushr 24) and 0xFF).toByte()
            out[i * 4 + 1] = ((h[i] ushr 16) and 0xFF).toByte()
            out[i * 4 + 2] = ((h[i] ushr 8) and 0xFF).toByte()
            out[i * 4 + 3] = (h[i] and 0xFF).toByte()
        }
        return out
    }
}

/**
 * Computes the deterministic `keyId` for an X.509 SubjectPublicKeyInfo DER encoding:
 * `base64url(SHA-256(spkiDer))`.
 */
public fun computeKeyId(spkiDer: ByteArray): String {
    require(spkiDer.isNotEmpty()) { "SPKI DER bytes must not be empty" }
    return Base64Url.encode(Sha256.digest(spkiDer))
}

/**
 * Encodes [this] byte array as lowercase hexadecimal for diagnostics and test vectors.
 */
public fun ByteArray.toHexString(): String {
    val hex = "0123456789abcdef"
    val sb = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        sb.append(hex[v ushr 4])
        sb.append(hex[v and 0x0F])
    }
    return sb.toString()
}
