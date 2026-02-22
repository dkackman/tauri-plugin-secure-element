package net.kackman.secureelement

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import net.kackman.secureelement.BuildConfig
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.Executor

@InvokeArg
class PingArgs {
    var value: String? = null
}

@InvokeArg
class GenerateSecureKeyArgs {
    var keyName: String = ""
    var authMode: String? = null // "none", "pinOrBiometric", or "biometricOnly"
}

@InvokeArg
class ListKeysArgs {
    var keyName: String? = null
    var publicKey: String? = null
}

@InvokeArg
class SignWithKeyArgs {
    var keyName: String = ""
    var data: ByteArray = byteArrayOf()
}

@InvokeArg
class DeleteKeyArgs {
    var keyName: String? = null
    var publicKey: String? = null
    // Note: At least one of keyName or publicKey must be provided.
}

@TauriPlugin
class SecureKeysPlugin(
    private val activity: Activity,
) : Plugin(activity) {
    companion object {
        private const val TAG = "SecureKeysPlugin"
    }

    private fun sanitizeError(
        detailedMessage: String,
        genericMessage: String,
    ): String =
        if (BuildConfig.DEBUG) {
            detailedMessage
        } else {
            genericMessage
        }

    private fun sanitizeErrorWithKeyName(
        keyName: String,
        operation: String,
    ): String =
        if (BuildConfig.DEBUG) {
            "$operation: $keyName"
        } else {
            operation
        }

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val executor: Executor = ContextCompat.getMainExecutor(activity)

    private fun getKeyEntry(keyName: String): KeyStore.PrivateKeyEntry? = keyStore.getEntry(keyName, null) as? KeyStore.PrivateKeyEntry

    /**
     * Exports the public key in X9.62 uncompressed point format (65 bytes).
     * Format: 0x04 + X coordinate (32 bytes) + Y coordinate (32 bytes)
     * This matches the iOS/macOS SecKeyCopyExternalRepresentation format.
     */
    private fun exportPublicKeyBase64(entry: KeyStore.PrivateKeyEntry): String? {
        val publicKey = entry.certificate?.publicKey as? ECPublicKey ?: return null
        val point = publicKey.w

        // Get X and Y as byte arrays, ensuring exactly 32 bytes each
        val xBytes = bigIntegerTo32Bytes(point.affineX)
        val yBytes = bigIntegerTo32Bytes(point.affineY)

        // Build uncompressed point: 0x04 + X + Y
        val uncompressedPoint = ByteArray(65)
        uncompressedPoint[0] = 0x04
        System.arraycopy(xBytes, 0, uncompressedPoint, 1, 32)
        System.arraycopy(yBytes, 0, uncompressedPoint, 33, 32)

        return Base64.encodeToString(uncompressedPoint, Base64.NO_WRAP)
    }

    /**
     * Converts a BigInteger to exactly 32 bytes.
     * Handles both cases:
     * - BigInteger has leading zero byte (sign bit) that needs trimming
     * - BigInteger has fewer than 32 bytes and needs left-padding with zeros
     */
    private fun bigIntegerTo32Bytes(value: java.math.BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == 32 -> {
                bytes
            }

            bytes.size > 32 -> {
                // BigInteger prepends a zero byte if high bit is set (to indicate positive)
                // For P-256 coordinates, this means 33 bytes with leading 0x00
                bytes.copyOfRange(bytes.size - 32, bytes.size)
            }

            else -> {
                // Pad with leading zeros
                val padded = ByteArray(32)
                System.arraycopy(bytes, 0, padded, 32 - bytes.size, bytes.size)
                padded
            }
        }
    }

    private fun checkKeyNotExists(
        keyName: String,
        operation: String,
        invoke: Invoke,
    ): Boolean {
        if (keyStore.containsAlias(keyName)) {
            val message = sanitizeErrorWithKeyName(keyName, "Key already exists")
            Log.e(TAG, "$operation: Key already exists: $keyName")
            invoke.reject(message)
            return false
        }
        return true
    }

    private fun checkKeyExists(
        keyName: String,
        operation: String,
        invoke: Invoke,
    ): Boolean {
        if (!keyStore.containsAlias(keyName)) {
            val message = sanitizeErrorWithKeyName(keyName, "Key not found")
            Log.e(TAG, "$operation: Key not found: $keyName")
            invoke.reject(message)
            return false
        }
        return true
    }

    /**
     * Builds a BiometricPrompt.PromptInfo for authentication.
     * Always allows both biometric and device credential (PIN/pattern/password).
     * The key itself enforces its actual requirements - if a key was created with
     * biometric-only, PIN authentication will fail at the cryptographic level.
     */
    private fun buildPromptInfo(subtitle: String): BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo
            .Builder()
            .setTitle("Authentication Required")
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            ).build()

    private fun buildKeyGenParameterSpec(
        alias: String,
        authMode: String,
        useSecureElement: Boolean,
    ): KeyGenParameterSpec =
        KeyGenParameterSpec
            .Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply {
                when (authMode) {
                    "none" -> {
                        // No authentication required
                    }

                    "biometricOnly" -> {
                        // Note: biometricOnly is rejected at generateSecureKey() for API < 30
                        setUserAuthenticationRequired(true)
                        setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    }

                    else -> {
                        // "pinOrBiometric" or default - allow both biometric and device credential
                        setUserAuthenticationRequired(true)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            setUserAuthenticationParameters(
                                0,
                                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                            )
                        } else {
                            @Suppress("DEPRECATION")
                            setUserAuthenticationValidityDurationSeconds(0)
                        }
                    }
                }
                if (useSecureElement) {
                    setIsStrongBoxBacked(true)
                }
            }.build()

    /**
     * Check if Secure Element (StrongBox) is supported on this device.
     * StrongBox requires Android API level 28 (Android 9) or higher.
     */
    private fun isSecureElementSupported(): Boolean {
        // StrongBox requires API level 28+
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return false
        }

        try {
            return activity.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        } catch (e: Exception) {
            Log.e(TAG, "Error checking for StrongBox feature", e)
            throw e
        }
    }

    /**
     * Check if Trusted Execution Environment (TEE) / hardware-backed keystore is supported.
     * This checks if keys can be stored in hardware-backed storage (TEE) even without
     * StrongBox, i.e. ARM TrustZone
     */
    private fun isTeeSupported(): Boolean {
        // TEE requires API level 18+ for hardware-backed keystore
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
            return false
        }

        // Try to create a test key and check if it's hardware-backed
        // Use a unique test key name that's unlikely to collide with real keys
        val testAlias = "__tee_test_${UUID.randomUUID()}"

        try {
            val keyPairGenerator =
                KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore",
                )

            val keyGenParameterSpec =
                KeyGenParameterSpec
                    .Builder(
                        testAlias,
                        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                    ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()

            keyPairGenerator.initialize(keyGenParameterSpec)
            keyPairGenerator.generateKeyPair()

            // Check if the key is hardware-backed
            val entry = keyStore.getEntry(testAlias, null) as? KeyStore.PrivateKeyEntry
            if (entry != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val privateKey = entry.privateKey as? ECPrivateKey
                if (privateKey != null) {
                    val keyFactory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                    val keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)
                    return keyInfo.isInsideSecureHardware
                }
            }

            // If we can't check KeyInfo (API < 23), assume TEE is available if key creation succeeded
            // and we're on API 18+ (hardware-backed keystore was introduced)
            return true
        } catch (e: Exception) {
            Log.e(TAG, "TEE check failed", e)
            return false
        } finally {
            try {
                keyStore.deleteEntry(testAlias)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to clean up test key", e)
            }
        }
    }

    /**
     * Check if the device has a secure lock screen (PIN, pattern, or password).
     * Returns null if a secure lock is configured, or an error message if not.
     */
    private fun checkDeviceSecure(): String? {
        val keyguardManager =
            activity.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
                ?: return "Unable to check device security status."

        // isDeviceSecure() returns true if the device has a secure lock screen
        // (PIN, pattern, password, or biometric that requires one of these as backup)
        return if (keyguardManager.isDeviceSecure) {
            null // Device is secure
        } else {
            "No secure lock screen is configured. Please set up a PIN, pattern, or password in Settings."
        }
    }

    /**
     * Check if strong biometric authentication is available and enrolled.
     * Returns null if biometrics are available, or an error message if not.
     */
    private fun checkBiometricAvailability(): String? {
        val biometricManager = BiometricManager.from(activity)
        return when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                null
            }

            // Biometrics available
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                "Biometric hardware is not available on this device."
            }

            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                "Biometric hardware is currently unavailable."
            }

            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                "No biometric authentication is enrolled. Please set up fingerprint or face authentication in Settings."
            }

            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {
                "A security update is required before biometric authentication can be used."
            }

            else -> {
                "Biometric authentication is not available on this device."
            }
        }
    }

    @Command
    fun ping(invoke: Invoke) {
        val args = invoke.parseArgs(PingArgs::class.java)
        val ret = JSObject()
        ret.put("value", args.value ?: "")
        invoke.resolve(ret)
    }

    /**
     * Detect if running on an Android emulator
     */
    private fun isEmulator(): Boolean =
        (
            Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for x86") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) ||
                Build.PRODUCT == "google_sdk" ||
                Build.PRODUCT == "sdk_gphone_x86" ||
                Build.PRODUCT == "sdk_gphone_x86_64" ||
                Build.PRODUCT == "sdk_gphone64_arm64" ||
                Build.HARDWARE.contains("goldfish") ||
                Build.HARDWARE.contains("ranchu")
        )

    @Command
    fun checkSecureElementSupport(invoke: Invoke) {
        try {
            // StrongBox = discrete physical security chip
            val discrete = isSecureElementSupported()
            // TEE/TrustZone = on-die isolated security core
            val integrated = isTeeSupported()
            // Android doesn't have firmware-only TPM tier
            val firmware = false
            // Check if running in emulator
            val emulated = isEmulator()
            // API 30+ (Android 11+) supports biometric-only enforcement at key level
            val canEnforceBiometricOnly = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

            // Determine strongest backing (discrete > integrated > firmware > none)
            val strongest =
                when {
                    discrete -> "discrete"
                    integrated -> "integrated"
                    firmware -> "firmware"
                    else -> "none"
                }

            val ret = JSObject()
            ret.put("discrete", discrete)
            ret.put("integrated", integrated)
            ret.put("firmware", firmware)
            ret.put("emulated", emulated)
            ret.put("strongest", strongest)
            ret.put("canEnforceBiometricOnly", canEnforceBiometricOnly)
            invoke.resolve(ret)
        } catch (e: Exception) {
            Log.e(TAG, "Error in checkSecureElementSupport", e)
            val detailedMessage = "Failed to check Secure Element support: ${e.message ?: e.javaClass.simpleName}"
            val errorMessage = sanitizeError(detailedMessage, "Failed to check Secure Element support")
            invoke.reject(errorMessage)
        }
    }

    @Command
    fun generateSecureKey(invoke: Invoke) {
        try {
            if (!isSecureElementSupported() && !isTeeSupported()) {
                invoke.reject(
                    "Hardware-backed keystore is not available on this device. Secure element keys require hardware-backed storage.",
                )
                return
            }

            val args = invoke.parseArgs(GenerateSecureKeyArgs::class.java)

            if (!checkKeyNotExists(args.keyName, "generateSecureKey", invoke)) {
                return
            }

            // Check if Secure Element (StrongBox) is supported upfront
            val useSecureElement = isSecureElementSupported()
            val authMode = args.authMode ?: "pinOrBiometric"

            // Validate authentication mode requirements
            when (authMode) {
                "biometricOnly" -> {
                    // Reject biometricOnly on API < 30 - cannot enforce at key level
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
                        invoke.reject(
                            "biometricOnly authentication mode requires Android 11 (API 30) or higher. " +
                                "Use 'pinOrBiometric' or 'none' on this device.",
                        )
                        return
                    }
                    // Check that biometrics are available and enrolled
                    val biometricError = checkBiometricAvailability()
                    if (biometricError != null) {
                        invoke.reject(
                            "biometricOnly authentication mode requires biometric authentication. $biometricError",
                        )
                        return
                    }
                }

                "pinOrBiometric" -> {
                    // Check that device has a secure lock screen
                    val securityError = checkDeviceSecure()
                    if (securityError != null) {
                        invoke.reject(
                            "pinOrBiometric authentication mode requires a secure lock screen. $securityError",
                        )
                        return
                    }
                }
                // "none" - no validation required
            }

            var keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

            var keyGenParameterSpec = buildKeyGenParameterSpec(args.keyName, authMode, useSecureElement)

            // Track whether we successfully used StrongBox
            var usedStrongBox = useSecureElement

            try {
                keyPairGenerator.initialize(keyGenParameterSpec)
                keyPairGenerator.generateKeyPair()
                if (useSecureElement) {
                    Log.i(TAG, "generateSecureKey: Key created with StrongBox backing")
                }
            } catch (e: Exception) {
                // If Secure Element was requested but failed, fall back to regular hardware-backed storage
                if (useSecureElement) {
                    Log.w(
                        TAG,
                        "generateSecureKey: StrongBox key creation failed, falling back to TEE. " +
                            "Reason: ${e.message ?: e.javaClass.simpleName}",
                    )

                    // Clean up any partial key entry left by the failed StrongBox attempt
                    try {
                        keyStore.deleteEntry(args.keyName)
                    } catch (deleteEx: Exception) {
                        Log.w(TAG, "generateSecureKey: Failed to clean up partial StrongBox key", deleteEx)
                    }

                    // Create a new KeyPairGenerator instance since it can't be reinitialized
                    keyPairGenerator =
                        KeyPairGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_EC,
                            "AndroidKeyStore",
                        )

                    keyGenParameterSpec = buildKeyGenParameterSpec(args.keyName, authMode, false)

                    keyPairGenerator.initialize(keyGenParameterSpec)
                    keyPairGenerator.generateKeyPair()
                    usedStrongBox = false
                    Log.i(TAG, "generateSecureKey: Key created with TEE backing (StrongBox fallback)")
                } else {
                    // Re-throw if StrongBox wasn't expected
                    throw e
                }
            }

            // Get the public key
            val entry =
                getKeyEntry(args.keyName)
                    ?: throw Exception("Failed to get key entry after key generation")

            val publicKeyBase64 =
                exportPublicKeyBase64(entry)
                    ?: throw Exception("Failed to get public key after key generation")

            val ret = JSObject()
            ret.put("publicKey", publicKeyBase64)
            ret.put("keyName", args.keyName)
            invoke.resolve(ret)
        } catch (e: Exception) {
            val detailedMessage = "Failed to create key: ${e.message ?: e.javaClass.simpleName}"
            val errorMessage = sanitizeError(detailedMessage, "Failed to create key")
            Log.e(TAG, "generateSecureKey: $detailedMessage", e)
            invoke.reject(errorMessage)
        }
    }

    @Command
    fun listKeys(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(ListKeysArgs::class.java)
            val keys = mutableListOf<Map<String, Any?>>()
            val aliases = keyStore.aliases()

            while (aliases.hasMoreElements()) {
                val keyName = aliases.nextElement() as String

                // Apply key name filter if provided
                if (args.keyName != null && args.keyName != keyName) {
                    continue
                }

                // Get the public key
                val entry = getKeyEntry(keyName) ?: continue
                val publicKeyBase64 = exportPublicKeyBase64(entry) ?: continue

                // Apply public key filter if provided
                if (args.publicKey != null && args.publicKey != publicKeyBase64) {
                    continue
                }

                val keyInfo =
                    mapOf(
                        "keyName" to keyName,
                        "publicKey" to publicKeyBase64,
                    )
                keys.add(keyInfo)
            }

            // Use resolveObject with Map to ensure proper JSON serialization
            val ret = mapOf("keys" to keys)
            invoke.resolveObject(ret)
        } catch (e: Exception) {
            val detailedMessage = "Failed to list keys: ${e.message}"
            val errorMessage = sanitizeError(detailedMessage, "Failed to list keys")
            Log.e(TAG, "listKeys: $detailedMessage", e)
            invoke.reject(errorMessage)
        }
    }

    /**
     * Checks if an exception indicates user authentication is required
     */
    private fun isUserNotAuthenticatedException(e: Exception): Boolean {
        // Check if the exception is UserNotAuthenticatedException
        // This exception was added in API 23, same as KeyGenParameterSpec
        if (e is android.security.keystore.UserNotAuthenticatedException ||
            e.cause is android.security.keystore.UserNotAuthenticatedException
        ) {
            return true
        }

        // Also check for KeyStoreException with "Key user not authenticated" message
        // Some Android versions/implementations throw KeyStoreException instead of UserNotAuthenticatedException
        if (e is android.security.KeyStoreException) {
            val message = e.message ?: ""
            // Check for the specific error message indicating user not authenticated
            // Error code -26 corresponds to KEY_USER_NOT_AUTHENTICATED
            if (message.contains("Key user not authenticated", ignoreCase = true) ||
                message.contains("KEY_USER_NOT_AUTHENTICATED", ignoreCase = true) ||
                message.contains("internal Keystore code: -26", ignoreCase = true)
            ) {
                return true
            }
        }

        // Check cause as well
        if (e.cause is android.security.KeyStoreException) {
            val message = e.cause?.message ?: ""
            if (message.contains("Key user not authenticated", ignoreCase = true) ||
                message.contains("KEY_USER_NOT_AUTHENTICATED", ignoreCase = true) ||
                message.contains("internal Keystore code: -26", ignoreCase = true)
            ) {
                return true
            }
        }

        return false
    }

    /**
     * Performs the actual signing operation with an already-initialized signature object
     */
    private fun performSign(
        signature: Signature,
        data: ByteArray,
    ): ByteArray {
        signature.update(data)
        return signature.sign()
    }

    /**
     * Shows BiometricPrompt and performs signing after successful authentication
     */
    private fun signWithBiometricPrompt(
        entry: KeyStore.PrivateKeyEntry,
        data: ByteArray,
        keyName: String,
        invoke: Invoke,
    ) {
        val fragmentActivity =
            activity as? FragmentActivity
                ?: run {
                    invoke.reject("Activity is not a FragmentActivity - cannot show authentication UI")
                    return
                }

        // Create a new signature object for use with CryptoObject
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(entry.privateKey)

        val cryptoObject = BiometricPrompt.CryptoObject(signature)

        val biometricPrompt =
            BiometricPrompt(
                fragmentActivity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        try {
                            // Use the authenticated signature from the result
                            val authenticatedSignature =
                                result.cryptoObject?.signature
                                    ?: run {
                                        invoke.reject("No signature in crypto object after authentication")
                                        return
                                    }

                            val signatureBytes = performSign(authenticatedSignature, data)

                            // Convert ByteArray to List<Int> (unsigned bytes 0-255) for proper JSON serialization
                            val signatureArray = signatureBytes.map { it.toInt() and 0xFF }
                            invoke.resolveObject(mapOf("signature" to signatureArray))
                        } catch (e: Exception) {
                            val detailedMessage = "Failed to sign after authentication: ${e.message}"
                            val errorMessage = sanitizeError(detailedMessage, "Failed to sign")
                            Log.e(TAG, "signWithKey (post-auth): $detailedMessage", e)
                            invoke.reject(errorMessage)
                        }
                    }

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence,
                    ) {
                        super.onAuthenticationError(errorCode, errString)
                        val detailedMessage = "Authentication failed: $errString (code: $errorCode)"
                        val errorMessage = sanitizeError(detailedMessage, "Authentication failed")
                        Log.e(TAG, "signWithKey: $detailedMessage")
                        invoke.reject(errorMessage)
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        // This is called when a biometric is valid but not recognized
                        // Don't reject here - the user can try again
                        Log.d(TAG, "signWithKey: Authentication attempt failed, user can retry")
                    }
                },
            )

        // Build prompt info
        val promptInfo = buildPromptInfo("Sign with key: $keyName")

        // Show authentication UI with CryptoObject
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }

    @Command
    fun signWithKey(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(SignWithKeyArgs::class.java)

            if (!checkKeyExists(args.keyName, "signWithKey", invoke)) {
                return
            }

            // Get the private key entry
            val entry =
                getKeyEntry(args.keyName)
                    ?: run {
                        invoke.reject("Failed to get key entry")
                        return
                    }

            // Initialize the signature object
            // Note: Android's SHA256withECDSA hashes the data internally,
            // while iOS hashes first then signs the digest.
            // Both approaches produce valid ECDSA signatures.
            val signature = Signature.getInstance("SHA256withECDSA")

            // Try to sign directly first - this will work for keys that don't require auth
            // For auth-required keys, this will throw UserNotAuthenticatedException
            try {
                signature.initSign(entry.privateKey)
                val signatureBytes = performSign(signature, args.data)

                // Success - key didn't require authentication
                val signatureArray = signatureBytes.map { it.toInt() and 0xFF }
                invoke.resolveObject(mapOf("signature" to signatureArray))
            } catch (e: Exception) {
                // Check if this is an authentication-required error
                if (isUserNotAuthenticatedException(e)) {
                    Log.d(TAG, "Key requires authentication, showing BiometricPrompt")
                    signWithBiometricPrompt(entry, args.data, args.keyName, invoke)
                } else {
                    // Some other error - not auth related
                    val detailedMessage = "Failed to sign: ${e.message}"
                    val errorMessage = sanitizeError(detailedMessage, "Failed to sign")
                    Log.e(TAG, "signWithKey: $detailedMessage", e)
                    invoke.reject(errorMessage)
                }
            }
        } catch (e: Exception) {
            val detailedMessage = "Failed to sign: ${e.message}"
            val errorMessage = sanitizeError(detailedMessage, "Failed to sign")
            Log.e(TAG, "signWithKey: $detailedMessage", e)
            invoke.reject(errorMessage)
        }
    }

    @Command
    fun deleteKey(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(DeleteKeyArgs::class.java)

            // If keyName is provided, delete by name (fast path)
            if (args.keyName != null) {
                val keyName = args.keyName!!

                if (!keyStore.containsAlias(keyName)) {
                    // Key doesn't exist, but we'll return success anyway (idempotent)
                    val ret = JSObject()
                    ret.put("success", true)
                    invoke.resolve(ret)
                    return
                }

                try {
                    keyStore.deleteEntry(keyName)
                    val ret = JSObject()
                    ret.put("success", true)
                    invoke.resolve(ret)
                } catch (e: Exception) {
                    val detailedMessage = "Failed to delete key: ${e.message}"
                    val errorMessage = sanitizeError(detailedMessage, "Failed to delete key")
                    Log.e(TAG, "deleteKey: $detailedMessage", e)
                    invoke.reject(errorMessage)
                }
                return
            }

            // If publicKey is provided, find the key by public key and delete it
            val targetPublicKey = args.publicKey
            if (targetPublicKey == null) {
                invoke.reject("Either keyName or publicKey must be provided")
                return
            }

            val aliases = keyStore.aliases()
            var found = false

            while (aliases.hasMoreElements()) {
                val keyName = aliases.nextElement() as String

                // Get the public key
                val entry = getKeyEntry(keyName) ?: continue
                val publicKeyBase64 = exportPublicKeyBase64(entry) ?: continue

                // Check if this key matches the target public key
                if (publicKeyBase64 == targetPublicKey) {
                    try {
                        keyStore.deleteEntry(keyName)
                        found = true
                        break
                    } catch (e: Exception) {
                        val detailedMessage = "Failed to delete key: ${e.message}"
                        val errorMessage = sanitizeError(detailedMessage, "Failed to delete key")
                        Log.e(TAG, "deleteKey: $detailedMessage", e)
                        invoke.reject(errorMessage)
                        return
                    }
                }
            }

            // Return success whether key was found or not (idempotent)
            val ret = JSObject()
            ret.put("success", true)
            invoke.resolve(ret)
        } catch (e: Exception) {
            val detailedMessage = "Failed to delete key: ${e.message}"
            val errorMessage = sanitizeError(detailedMessage, "Failed to delete key")
            Log.e(TAG, "deleteKey: $detailedMessage", e)
            invoke.reject(errorMessage)
        }
    }
}
