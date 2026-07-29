package net.kackman.secureelement

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.biometric.BiometricPrompt
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
        // First byte must be non-zero (and high bit clear) so the magnitude is a
        // genuine 32 significant bytes: a leading 0x00 would make toByteArray()
        // return 31 bytes, and a high bit would add a 33rd sign byte.
        val input = BigInteger(1, ByteArray(32) { (it + 1).toByte() })
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

    // ── key alias namespacing ────────────────────────────────────────────────
    // Every key is stored under a prefixed alias so the plugin only ever sees
    // keys it created. listKeys returns the user-facing name with the prefix
    // stripped, so aliasFor/keyNameFromAlias must round-trip exactly.

    @Test
    fun `aliasFor then keyNameFromAlias round-trips`() {
        for (name in listOf("mykey", "my-key_1", "a", "z".repeat(64))) {
            val alias = SecureKeysPlugin.aliasFor(name)
            assertEquals(name, SecureKeysPlugin.keyNameFromAlias(alias))
        }
    }

    @Test
    fun `aliasFor applies the plugin prefix`() {
        assertEquals("net.kackman.secureelement.k", SecureKeysPlugin.aliasFor("k"))
    }

    @Test
    fun `keyNameFromAlias rejects foreign aliases`() {
        // Aliases another library would create (no plugin prefix) are not ours.
        assertNull(SecureKeysPlugin.keyNameFromAlias("mykey"))
        assertNull(SecureKeysPlugin.keyNameFromAlias("AndroidKeyStore_default"))
        assertNull(SecureKeysPlugin.keyNameFromAlias(""))
    }

    // ── error sanitization ───────────────────────────────────────────────────
    // Mirrors src/error_sanitize.rs on the Rust side, but parameterized on
    // isDebug rather than gated on BuildConfig.DEBUG at compile time, so both
    // branches run in a single JVM test process instead of needing a release build.

    @Test
    fun `sanitizeErrorMessage returns detailed message when debug`() {
        assertEquals(
            "detailed",
            SecureKeysPlugin.sanitizeErrorMessage(true, "detailed", "generic"),
        )
    }

    @Test
    fun `sanitizeErrorMessage returns generic message when not debug`() {
        assertEquals(
            "generic",
            SecureKeysPlugin.sanitizeErrorMessage(false, "detailed", "generic"),
        )
    }

    @Test
    fun `sanitizeErrorWithKeyNameMessage includes key name when debug`() {
        assertEquals(
            "Key not found: my-key",
            SecureKeysPlugin.sanitizeErrorWithKeyNameMessage(true, "my-key", "Key not found"),
        )
    }

    @Test
    fun `sanitizeErrorWithKeyNameMessage omits key name when not debug`() {
        assertEquals(
            "Key not found",
            SecureKeysPlugin.sanitizeErrorWithKeyNameMessage(false, "my-key", "Key not found"),
        )
    }

    // ── emulator classification ──────────────────────────────────────────────

    @Test
    fun `classifyEmulator is false for real-device build fields`() {
        assertFalse(
            SecureKeysPlugin.classifyEmulator(
                fingerprint = "google/panther/panther:14/UP1A.231005.007/1234:user/release-keys",
                model = "Pixel 7",
                manufacturer = "Google",
                brand = "google",
                device = "panther",
                product = "panther",
                hardware = "panther",
            ),
        )
    }

    @Test
    fun `classifyEmulator detects generic fingerprint`() {
        assertTrue(
            SecureKeysPlugin.classifyEmulator(
                fingerprint = "generic/sdk_gphone64_arm64/emu64a:14/UE1A.230829.036/1234:userdebug/dev-keys",
                model = "sdk_gphone64_arm64",
                manufacturer = "Google",
                brand = "google",
                device = "emu64a",
                product = "sdk_gphone64_arm64",
                hardware = "ranchu",
            ),
        )
    }

    @Test
    fun `classifyEmulator detects goldfish hardware`() {
        assertTrue(
            SecureKeysPlugin.classifyEmulator(
                fingerprint = "generic/sdk/generic:9/PSR1.180720.117/1234:eng/test-keys",
                model = "AOSP on IA Emulator",
                manufacturer = "unknown",
                brand = "generic",
                device = "generic",
                product = "sdk_x86",
                hardware = "goldfish",
            ),
        )
    }

    @Test
    fun `classifyEmulator detects Genymotion manufacturer`() {
        assertTrue(
            SecureKeysPlugin.classifyEmulator(
                fingerprint = "Genymotion/vbox86p/vbox86p:9/PPR1.180610.011/1234:userdebug/test-keys",
                model = "Custom Phone",
                manufacturer = "Genymotion",
                brand = "generic",
                device = "vbox86p",
                product = "vbox86p",
                hardware = "vbox86",
            ),
        )
    }

    // ── strongest backing tier ───────────────────────────────────────────────
    // Mirrors the equivalent precedence classification in windows.rs and
    // SecureEnclaveCore.swift: discrete > integrated > firmware > software.

    @Test
    fun `strongestBacking prefers discrete over everything`() {
        assertEquals("discrete", SecureKeysPlugin.strongestBacking(true, true, true))
    }

    @Test
    fun `strongestBacking prefers integrated over firmware`() {
        assertEquals("integrated", SecureKeysPlugin.strongestBacking(false, true, true))
    }

    @Test
    fun `strongestBacking falls back to firmware`() {
        assertEquals("firmware", SecureKeysPlugin.strongestBacking(false, false, true))
    }

    @Test
    fun `strongestBacking falls back to software when nothing else is available`() {
        assertEquals("software", SecureKeysPlugin.strongestBacking(false, false, false))
    }

    // ── user-not-authenticated classification ────────────────────────────────
    // android.security.KeyStoreException only exposes a no-arg public constructor
    // (its message-carrying constructor is framework-internal), so the
    // message-matching branches of isUserNotAuthenticatedException aren't
    // reachable from a plain-JUnit test; these cover the branches that are.

    @Test
    fun `isUserNotAuthenticatedException is true for the exception directly`() {
        assertTrue(
            SecureKeysPlugin.isUserNotAuthenticatedException(
                android.security.keystore.UserNotAuthenticatedException("locked"),
            ),
        )
    }

    @Test
    fun `isUserNotAuthenticatedException is true when it is the cause`() {
        val wrapped =
            RuntimeException(
                "wrapped",
                android.security.keystore.UserNotAuthenticatedException("locked"),
            )
        assertTrue(SecureKeysPlugin.isUserNotAuthenticatedException(wrapped))
    }

    @Test
    fun `isUserNotAuthenticatedException is false for an unrelated exception`() {
        assertFalse(SecureKeysPlugin.isUserNotAuthenticatedException(IllegalStateException("boom")))
    }

    @Test
    fun `isUserNotAuthenticatedException is false for an unrelated cause`() {
        val wrapped = RuntimeException("wrapped", IllegalStateException("boom"))
        assertFalse(SecureKeysPlugin.isUserNotAuthenticatedException(wrapped))
    }

    // ── error-code classification ────────────────────────────────────────────
    // The codes these produce are the only part of an error that survives
    // release-build sanitization, so an app branching on "the user cancelled"
    // vs "the key is gone" depends entirely on this mapping being right.

    @Test
    fun `dismissing the prompt classifies as cancellation, not failure`() {
        assertEquals(
            SecureKeysPlugin.ErrorCodes.USER_CANCELLED,
            SecureKeysPlugin.classifyBiometricError(BiometricPrompt.ERROR_NEGATIVE_BUTTON),
        )
        assertEquals(
            SecureKeysPlugin.ErrorCodes.USER_CANCELLED,
            SecureKeysPlugin.classifyBiometricError(BiometricPrompt.ERROR_USER_CANCELED),
        )
        assertEquals(
            SecureKeysPlugin.ErrorCodes.USER_CANCELLED,
            SecureKeysPlugin.classifyBiometricError(BiometricPrompt.ERROR_CANCELED),
        )
    }

    @Test
    fun `a prompt that times out counts as cancellation`() {
        assertEquals(
            SecureKeysPlugin.ErrorCodes.USER_CANCELLED,
            SecureKeysPlugin.classifyBiometricError(BiometricPrompt.ERROR_TIMEOUT),
        )
    }

    @Test
    fun `lockout is an authentication failure, not unavailable hardware`() {
        assertEquals(
            SecureKeysPlugin.ErrorCodes.AUTH_FAILED,
            SecureKeysPlugin.classifyBiometricError(BiometricPrompt.ERROR_LOCKOUT),
        )
        assertEquals(
            SecureKeysPlugin.ErrorCodes.AUTH_FAILED,
            SecureKeysPlugin.classifyBiometricError(BiometricPrompt.ERROR_LOCKOUT_PERMANENT),
        )
    }

    @Test
    fun `missing credentials classify as an insecure device`() {
        assertEquals(
            SecureKeysPlugin.ErrorCodes.DEVICE_NOT_SECURE,
            SecureKeysPlugin.classifyBiometricError(BiometricPrompt.ERROR_NO_BIOMETRICS),
        )
        assertEquals(
            SecureKeysPlugin.ErrorCodes.DEVICE_NOT_SECURE,
            SecureKeysPlugin.classifyBiometricError(BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL),
        )
    }

    @Test
    fun `an unrecognised biometric error falls back to internal`() {
        assertEquals(
            SecureKeysPlugin.ErrorCodes.INTERNAL,
            SecureKeysPlugin.classifyBiometricError(BiometricPrompt.ERROR_VENDOR),
        )
        assertEquals(SecureKeysPlugin.ErrorCodes.INTERNAL, SecureKeysPlugin.classifyBiometricError(9999))
    }

    // A key invalidated by a biometric enrollment change is unrecoverable, and
    // Android is the only platform that says so unambiguously. Reporting it as a
    // generic signing failure would leave callers retrying a key that can never
    // work again.

    @Test
    fun `a permanently invalidated key is reported as such`() {
        assertEquals(
            SecureKeysPlugin.ErrorCodes.KEY_INVALIDATED,
            SecureKeysPlugin.classifyKeyUseException(KeyPermanentlyInvalidatedException()),
        )
    }

    @Test
    fun `invalidation is detected through a wrapping exception`() {
        val wrapped = RuntimeException("wrapped", KeyPermanentlyInvalidatedException())
        assertEquals(
            SecureKeysPlugin.ErrorCodes.KEY_INVALIDATED,
            SecureKeysPlugin.classifyKeyUseException(wrapped),
        )
    }

    @Test
    fun `needing authentication is distinct from the key being destroyed`() {
        assertEquals(
            SecureKeysPlugin.ErrorCodes.AUTH_FAILED,
            SecureKeysPlugin.classifyKeyUseException(
                android.security.keystore.UserNotAuthenticatedException("locked"),
            ),
        )
    }

    @Test
    fun `an unrelated failure classifies as internal`() {
        assertEquals(
            SecureKeysPlugin.ErrorCodes.INTERNAL,
            SecureKeysPlugin.classifyKeyUseException(IllegalStateException("boom")),
        )
    }
}
