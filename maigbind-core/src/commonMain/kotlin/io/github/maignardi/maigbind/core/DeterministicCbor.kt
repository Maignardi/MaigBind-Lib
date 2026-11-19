package io.github.maignardi.maigbind.core

/**
 * Deterministic CBOR (RFC 8949 Section 4.2) encoder and strict decoder.
 *
 * Design rules enforced by both encoder and decoder:
 * - Integers use the shortest possible encoding (RFC 8949 §4.2.1).
 * - Definite lengths only; indefinite-length items are rejected.
 * - Map keys are UTF-8 text strings sorted by bytewise unsigned lexicographical order of their
 *   encoded CBOR bytes (RFC 8949 §4.2.1, Core Deterministic Encoding Requirements).
 * - Duplicate map keys are rejected on decode.
 * - Floating-point numbers are intentionally unsupported in [CanonicalValue] to avoid IEEE-754
 *   representation ambiguity across mobile and backend runtimes.
 */
public object DeterministicCbor {
    private const val MAJOR_UNSIGNED = 0
    private const val MAJOR_NEGATIVE = 1
    private const val MAJOR_BYTES = 2
    private const val MAJOR_TEXT = 3
    private const val MAJOR_ARRAY = 4
    private const val MAJOR_MAP = 5
    private const val MAJOR_SIMPLE = 7

    private const val SIMPLE_FALSE = 20
    private const val SIMPLE_TRUE = 21

    /**
     * Encodes a [CanonicalValue] into deterministic CBOR bytes.
     */
    public fun encode(value: CanonicalValue): ByteArray {
        val out = ByteBuffer()
        writeValue(out, value)
        return out.toByteArray()
    }

    /**
     * Decodes deterministic CBOR bytes into a [CanonicalValue].
     *
     * @throws IllegalArgumentException if [bytes] is malformed, non-deterministic, or contains
     * trailing data.
     */
    public fun decode(bytes: ByteArray): CanonicalValue {
        require(bytes.isNotEmpty()) { "CBOR input must not be empty" }
        val reader = CborReader(bytes)
        val value = reader.readValue()
        require(!reader.hasRemaining()) {
            "Unexpected trailing bytes after CBOR root item at offset ${reader.position}"
        }
        return value
    }

    private fun writeValue(
        out: ByteBuffer,
        value: CanonicalValue,
    ) {
        when (value) {
            is CanonicalValue.Int64 -> writeInt64(out, value.value)
            is CanonicalValue.Bool -> {
                val ai = if (value.value) SIMPLE_TRUE else SIMPLE_FALSE
                out.writeByte((MAJOR_SIMPLE shl 5) or ai)
            }
            is CanonicalValue.Bytes -> {
                val data = value.value
                writeTypeAndLength(out, MAJOR_BYTES, data.size.toLong())
                out.writeBytes(data)
            }
            is CanonicalValue.Text -> {
                val utf8 = value.value.encodeToByteArray()
                writeTypeAndLength(out, MAJOR_TEXT, utf8.size.toLong())
                out.writeBytes(utf8)
            }
            is CanonicalValue.ListValue -> {
                writeTypeAndLength(out, MAJOR_ARRAY, value.items.size.toLong())
                for (item in value.items) {
                    writeValue(out, item)
                }
            }
            is CanonicalValue.MapValue -> writeMap(out, value.entries)
        }
    }

    private fun writeMap(
        out: ByteBuffer,
        entries: Map<String, CanonicalValue>,
    ) {
        // RFC 8949 §4.2.1: sort by encoded CBOR key bytes in bytewise lexicographical order.
        val encodedEntries =
            entries.entries
                .map { (k, v) ->
                    val keyBuf = ByteBuffer()
                    val utf8 = k.encodeToByteArray()
                    writeTypeAndLength(keyBuf, MAJOR_TEXT, utf8.size.toLong())
                    keyBuf.writeBytes(utf8)
                    EncodedMapEntry(key = k, encodedKey = keyBuf.toByteArray(), value = v)
                }.sortedWith { a, b -> compareUnsignedBytes(a.encodedKey, b.encodedKey) }

        writeTypeAndLength(out, MAJOR_MAP, encodedEntries.size.toLong())
        for (entry in encodedEntries) {
            out.writeBytes(entry.encodedKey)
            writeValue(out, entry.value)
        }
    }

    private fun writeInt64(
        out: ByteBuffer,
        value: Long,
    ) {
        if (value >= 0) {
            writeTypeAndLength(out, MAJOR_UNSIGNED, value)
        } else {
            // CBOR negative int encodes (-1 - value) as unsigned magnitude.
            // Note: For Long.MIN_VALUE (-9223372036854775808), -1 - value = 9223372036854775807 = Long.MAX_VALUE.
            val magnitude = (-1L) - value
            writeTypeAndLength(out, MAJOR_NEGATIVE, magnitude)
        }
    }

    private fun writeTypeAndLength(
        out: ByteBuffer,
        majorType: Int,
        value: Long,
    ) {
        require(value >= 0) { "CBOR unsigned argument must be non-negative: $value" }
        val prefix = majorType shl 5
        when {
            value <= 23L -> out.writeByte(prefix or value.toInt())
            value <= 0xFFL -> {
                out.writeByte(prefix or 24)
                out.writeByte(value.toInt())
            }
            value <= 0xFFFFL -> {
                out.writeByte(prefix or 25)
                out.writeShort(value.toInt())
            }
            value <= 0xFFFF_FFFFL -> {
                out.writeByte(prefix or 26)
                out.writeInt(value.toInt())
            }
            else -> {
                out.writeByte(prefix or 27)
                out.writeLong(value)
            }
        }
    }

    private fun compareUnsignedBytes(
        a: ByteArray,
        b: ByteArray,
    ): Int {
        val minLen = minOf(a.size, b.size)
        for (i in 0 until minLen) {
            val ai = a[i].toInt() and 0xFF
            val bi = b[i].toInt() and 0xFF
            if (ai != bi) return ai - bi
        }
        return a.size - b.size
    }

    private class EncodedMapEntry(
        val key: String,
        val encodedKey: ByteArray,
        val value: CanonicalValue,
    )

    private class ByteBuffer {
        private var buf = ByteArray(128)
        private var size = 0

        fun writeByte(b: Int) {
            ensureCapacity(1)
            buf[size++] = (b and 0xFF).toByte()
        }

        fun writeShort(s: Int) {
            ensureCapacity(2)
            buf[size++] = ((s ushr 8) and 0xFF).toByte()
            buf[size++] = (s and 0xFF).toByte()
        }

        fun writeInt(v: Int) {
            ensureCapacity(4)
            buf[size++] = ((v ushr 24) and 0xFF).toByte()
            buf[size++] = ((v ushr 16) and 0xFF).toByte()
            buf[size++] = ((v ushr 8) and 0xFF).toByte()
            buf[size++] = (v and 0xFF).toByte()
        }

        fun writeLong(v: Long) {
            ensureCapacity(8)
            for (shift in 56 downTo 0 step 8) {
                buf[size++] = ((v ushr shift) and 0xFF).toByte()
            }
        }

        fun writeBytes(bytes: ByteArray) {
            ensureCapacity(bytes.size)
            bytes.copyInto(buf, destinationOffset = size)
            size += bytes.size
        }

        fun toByteArray(): ByteArray = buf.copyOf(size)

        private fun ensureCapacity(extra: Int) {
            val needed = size + extra
            if (needed <= buf.size) return
            var newSize = buf.size * 2
            while (newSize < needed) newSize *= 2
            buf = buf.copyOf(newSize)
        }
    }

    private class CborReader(
        private val data: ByteArray,
    ) {
        var position: Int = 0
            private set

        fun hasRemaining(): Boolean = position < data.size

        fun readValue(): CanonicalValue {
            val initial = readUnsignedByte()
            val major = (initial ushr 5) and 0x07
            val ai = initial and 0x1F

            return when (major) {
                MAJOR_UNSIGNED -> CanonicalValue.Int64(readCanonicalArgument(ai, allowLongMax = true))
                MAJOR_NEGATIVE -> {
                    val mag = readCanonicalArgument(ai, allowLongMax = true)
                    CanonicalValue.Int64(-1L - mag)
                }
                MAJOR_BYTES -> {
                    val len = readCanonicalLength(ai)
                    CanonicalValue.Bytes(readExactBytes(len))
                }
                MAJOR_TEXT -> {
                    val len = readCanonicalLength(ai)
                    val utf8 = readExactBytes(len)
                    CanonicalValue.Text(utf8.decodeToString(throwOnInvalidSequence = true))
                }
                MAJOR_ARRAY -> {
                    val count = readCanonicalLength(ai)
                    val items = ArrayList<CanonicalValue>(count)
                    repeat(count) {
                        items.add(readValue())
                    }
                    CanonicalValue.ListValue(items)
                }
                MAJOR_MAP -> {
                    val count = readCanonicalLength(ai)
                    val map = LinkedHashMap<String, CanonicalValue>(count)
                    var prevKeyBytes: ByteArray? = null
                    repeat(count) {
                        val keyStart = position
                        val keyVal = readValue()
                        require(keyVal is CanonicalValue.Text) {
                            "CBOR map keys must be UTF-8 text strings (offset $keyStart)"
                        }
                        val keyBytes = data.copyOfRange(keyStart, position)
                        val prev = prevKeyBytes
                        if (prev != null) {
                            val cmp = compareUnsignedBytes(prev, keyBytes)
                            require(cmp < 0) {
                                "Non-canonical CBOR map key order or duplicate key '${keyVal.value}'"
                            }
                        }
                        prevKeyBytes = keyBytes
                        map[keyVal.value] = readValue()
                    }
                    CanonicalValue.MapValue(map)
                }
                MAJOR_SIMPLE ->
                    when (ai) {
                        SIMPLE_FALSE -> CanonicalValue.Bool(false)
                        SIMPLE_TRUE -> CanonicalValue.Bool(true)
                        else -> throw IllegalArgumentException(
                            "Unsupported CBOR simple/float value (ai=$ai at offset ${position - 1})",
                        )
                    }
                else -> throw IllegalArgumentException(
                    "Unsupported CBOR major type $major at offset ${position - 1}",
                )
            }
        }

        private fun readCanonicalLength(ai: Int): Int {
            val arg = readCanonicalArgument(ai, allowLongMax = false)
            require(arg <= Int.MAX_VALUE && position + arg <= data.size) {
                "CBOR length $arg exceeds available input"
            }
            return arg.toInt()
        }

        private fun readCanonicalArgument(
            ai: Int,
            allowLongMax: Boolean,
        ): Long {
            require(ai != 31) { "Indefinite-length CBOR items are forbidden in deterministic CBOR" }
            require(ai <= 27) { "Reserved CBOR additional info: $ai" }
            return when {
                ai <= 23 -> ai.toLong()
                ai == 24 -> {
                    val v = readUnsignedByte().toLong()
                    require(v >= 24L) { "Non-minimal CBOR 1-byte integer: $v" }
                    v
                }
                ai == 25 -> {
                    val v = ((readUnsignedByte() shl 8) or readUnsignedByte()).toLong()
                    require(v > 0xFFL) { "Non-minimal CBOR 2-byte integer: $v" }
                    v
                }
                ai == 26 -> {
                    val v = (
                        (readUnsignedByte().toLong() shl 24) or
                            (readUnsignedByte().toLong() shl 16) or
                            (readUnsignedByte().toLong() shl 8) or
                            readUnsignedByte().toLong()
                    )
                    require(v > 0xFFFFL) { "Non-minimal CBOR 4-byte integer: $v" }
                    v
                }
                else -> {
                    var v = 0L
                    repeat(8) {
                        v = (v shl 8) or readUnsignedByte().toLong()
                    }
                    // Reject unsigned values > Long.MAX_VALUE (high bit set) and non-minimal 8-byte encodings.
                    require(v > 0xFFFF_FFFFL && (allowLongMax || v <= Int.MAX_VALUE)) {
                        "Non-minimal or out-of-range CBOR 8-byte integer"
                    }
                    v
                }
            }
        }

        private fun readUnsignedByte(): Int {
            require(position < data.size) { "Unexpected end of CBOR input at offset $position" }
            return data[position++].toInt() and 0xFF
        }

        private fun readExactBytes(length: Int): ByteArray {
            require(length >= 0 && position + length <= data.size) {
                "Unexpected end of CBOR byte/text string (need $length bytes at offset $position)"
            }
            val slice = data.copyOfRange(position, position + length)
            position += length
            return slice
        }
    }
}
