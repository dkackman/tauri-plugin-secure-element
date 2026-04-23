package net.kackman.secureelement

import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger

/**
 * Host-JVM unit tests for pure logic in SecureKeysPlugin.
 *
 * These run on the development machine without an Android device or emulator.
 * Hardware-backed keystore operations (key generation, signing) require an
 * Android device and are covered by the integration test app.
 */
class PluginUnitTest {
    // ── bigIntegerTo32Bytes ──────────────────────────────────────────────────
    // P-256 EC coordinates arrive from Android's KeyFactory as BigIntegers.
    // They must be normalised to exactly 32 bytes before being packed into
    // the X9.62 uncompressed point format (0x04 || X || Y).

    @Test
    fun `exact 32 bytes is returned unchanged`() {
        val input = BigInteger(1, ByteArray(32) { it.toByte() })
        val result = SecureKeysPlugin.bigIntegerTo32Bytes(input)
        assertEquals(32, result.size)
        // The 32-byte two's-complement representation of a positive BigInteger
        // whose bytes fit in 32 bytes is its toByteArray() directly.
        assertArrayEquals(
            input.toByteArray().let {
                if (it.size == 32) it else it.copyOfRange(it.size - 32, it.size)
            },
            result,
        )
    }

    @Test
    fun `33-byte BigInteger (sign byte) is trimmed to 32 bytes`() {
        // BigInteger.toByteArray() prepends 0x00 when the high bit is set to
        // indicate a positive number. P-256 coordinates fit in 32 bytes, so
        // the 33rd byte is always the sign byte and must be stripped.
        val bytes33 =
            ByteArray(33).also {
                it[0] = 0x00
                it[1] = 0xFF.toByte()
            }
        val big = BigInteger(bytes33)
        val result = SecureKeysPlugin.bigIntegerTo32Bytes(big)
        assertEquals(32, result.size)
        assertEquals(0xFF.toByte(), result[0])
    }

    @Test
    fun `short BigInteger is left-padded with zeros to 32 bytes`() {
        // A small coordinate value (e.g. leading zeros stripped by BigInteger)
        // must be padded back so the coordinate is at the right byte offset.
        val small = BigInteger.valueOf(0x42L)
        val result = SecureKeysPlugin.bigIntegerTo32Bytes(small)
        assertEquals(32, result.size)
        // All but the last byte should be zero
        for (i in 0 until 31) assertEquals("byte $i should be 0", 0, result[i].toInt())
        assertEquals(0x42.toByte(), result[31])
    }

    @Test
    fun `single byte value 1 is padded to 32 bytes`() {
        val result = SecureKeysPlugin.bigIntegerTo32Bytes(BigInteger.ONE)
        assertEquals(32, result.size)
        assertEquals(1.toByte(), result[31])
        for (i in 0 until 31) assertEquals(0.toByte(), result[i])
    }

    @Test
    fun `zero is represented as 32 zero bytes`() {
        val result = SecureKeysPlugin.bigIntegerTo32Bytes(BigInteger.ZERO)
        assertEquals(32, result.size)
        assertTrue(result.all { it == 0.toByte() })
    }

    @Test
    fun `max P-256 coordinate fits in 32 bytes`() {
        // Largest valid P-256 field element:
        // 2^256 - 2^224 + 2^192 + 2^96 - 1 (the prime p)
        // We just need to verify a 256-bit number with all high bits set works.
        val maxCoord = BigInteger(1, ByteArray(32) { 0xFF.toByte() })
        val result = SecureKeysPlugin.bigIntegerTo32Bytes(maxCoord)
        assertEquals(32, result.size)
        assertTrue(result.all { it == 0xFF.toByte() })
    }

    @Test
    fun `result is always exactly 32 bytes for various inputs`() {
        val inputs =
            listOf(
                BigInteger.ZERO,
                BigInteger.ONE,
                BigInteger.valueOf(255),
                BigInteger.valueOf(256),
                BigInteger.TWO.pow(128),
                BigInteger(1, ByteArray(32) { 0xFF.toByte() }),
            )
        for (input in inputs) {
            val result = SecureKeysPlugin.bigIntegerTo32Bytes(input)
            assertEquals("Expected 32 bytes for input $input", 32, result.size)
        }
    }
}
