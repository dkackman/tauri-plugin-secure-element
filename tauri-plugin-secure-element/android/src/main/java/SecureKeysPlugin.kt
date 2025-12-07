package app.tauri.plugin.secureelement

import android.app.Activity
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
import app.tauri.plugin.secureelement.BuildConfig
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
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
    var keyName: String = ""
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

    private val keyStoreAliasPrefix = "secure_element_"
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val executor: Executor = ContextCompat.getMainExecutor(activity)

    private fun getKeyAlias(keyName: String): String = "$keyStoreAliasPrefix$keyName"

    private fun getKeyEntry(alias: String): KeyStore.PrivateKeyEntry? = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry

    private fun exportPublicKeyBase64(entry: KeyStore.PrivateKeyEntry): String? {
        val publicKey = entry.certificate?.publicKey ?: return null
        val publicKeyBytes = publicKey.encoded
        return Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
    }

    private fun checkKeyNotExists(
        keyName: String,
        alias: String,
        operation: String,
        invoke: Invoke,
    ): Boolean {
        if (keyStore.containsAlias(alias)) {
            val message = sanitizeErrorWithKeyName(keyName, "Key already exists")
            Log.e(TAG, "$operation: Key already exists: $keyName")
            invoke.reject(message)
            return false
        }
        return true
    }

    private fun checkKeyExists(
        keyName: String,
        alias: String,
        operation: String,
        invoke: Invoke,
    ): Boolean {
        if (!keyStore.containsAlias(alias)) {
            val message = sanitizeErrorWithKeyName(keyName, "Key not found")
            Log.e(TAG, "$operation: Key not found: $keyName")
            invoke.reject(message)
            return false
        }
        return true
    }

    /**
     * Data class to hold key authentication information
     */
    private data class KeyAuthInfo(
        val requiresAuthentication: Boolean,
        val isBiometricOnly: Boolean,
    )

    /**
     * Gets the KeyInfo for a key, if available
     */
    private fun getKeyInfo(alias: String): KeyInfo? {
        return try {
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: return null
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val privateKey = entry.privateKey as? ECPrivateKey ?: return null
                val keyFactory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                keyFactory.getKeySpec(privateKey, KeyInfo::class.java)
            } else {
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to get KeyInfo", e)
            null
        }
    }

    /**
     * Checks if a key requires user authentication by examining its KeyInfo
     * Returns true if authentication is required, false if not, or null if it cannot be determined
     */
    private fun keyRequiresAuthentication(alias: String): Boolean? {
        return try {
            val keyInfo = getKeyInfo(alias) ?: return null
            keyInfo.isUserAuthenticationRequired
        } catch (e: Exception) {
            Log.w(TAG, "Failed to check key authentication requirements", e)
            null
        }
    }

    /**
     * Gets detailed authentication info for a key
     * Returns KeyAuthInfo with authentication requirements, or null if cannot be determined
     */
    private fun getKeyAuthInfo(alias: String): KeyAuthInfo? {
        return try {
            val keyInfo = getKeyInfo(alias) ?: return null
            val requiresAuth = keyInfo.isUserAuthenticationRequired

            // Determine if biometric-only (API 30+)
            val isBiometricOnly =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && requiresAuth) {
                    // Check if DEVICE_CREDENTIAL is NOT allowed
                    val authType = keyInfo.userAuthenticationType
                    (authType and KeyProperties.AUTH_DEVICE_CREDENTIAL) == 0
                } else {
                    // Pre-API 30: Can't determine, assume false (allow PIN)
                    false
                }

            KeyAuthInfo(requiresAuth, isBiometricOnly)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to get key auth info", e)
            null
        }
    }

    /**
     * Builds a BiometricPrompt.PromptInfo based on key's authentication requirements
     */
    private fun buildPromptInfoForKey(
        authInfo: KeyAuthInfo,
        subtitle: String,
    ): BiometricPrompt.PromptInfo =
        if (authInfo.isBiometricOnly) {
            // Biometric-only: cannot set DEVICE_CREDENTIAL, must provide negative button
            BiometricPrompt.PromptInfo
                .Builder()
                .setTitle("Biometric Authentication Required")
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("Cancel")
                .build()
        } else {
            // PIN or biometric: when DEVICE_CREDENTIAL is allowed, negative button cannot be set
            BiometricPrompt.PromptInfo
                .Builder()
                .setTitle("Authentication Required")
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                ).build()
        }

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
                        setUserAuthenticationRequired(true)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            // API 30+: Can specify biometric-only at key level
                            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                        } else {
                            // Pre-API 30: Cannot enforce biometric-only at key level
                            // Will enforce at BiometricPrompt level during signing
                            @Suppress("DEPRECATION")
                            setUserAuthenticationValidityDurationSeconds(0)
                        }
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
        val testAlias = "${keyStoreAliasPrefix}tee_test_${System.currentTimeMillis()}"

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
                    val isHardwareBacked = keyInfo.isInsideSecureHardware

                    // Clean up test key
                    keyStore.deleteEntry(testAlias)

                    return isHardwareBacked
                }
            }

            // If we can't check KeyInfo (API < 23), assume TEE is available if key creation succeeded
            // and we're on API 18+ (hardware-backed keystore was introduced)
            keyStore.deleteEntry(testAlias)
            return true
        } catch (e: Exception) {
            Log.e(TAG, "TEE check failed", e)
            // Clean up test key if it was created
            try {
                if (keyStore.containsAlias(testAlias)) {
                    keyStore.deleteEntry(testAlias)
                }
            } catch (cleanupException: Exception) {
                Log.w(TAG, "Failed to clean up test key", cleanupException)
            }
            return false
        }
    }

    @Command
    fun ping(invoke: Invoke) {
        val args = invoke.parseArgs(PingArgs::class.java)
        val ret = JSObject()
        ret.put("value", args.value ?: "")
        invoke.resolve(ret)
    }

    @Command
    fun checkSecureElementSupport(invoke: Invoke) {
        try {
            val secureElementSupported = isSecureElementSupported()
            val teeSupported = isTeeSupported()
            val ret = JSObject()
            ret.put("secureElementSupported", secureElementSupported)
            ret.put("teeSupported", teeSupported)
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
            val args = invoke.parseArgs(GenerateSecureKeyArgs::class.java)
            val alias = getKeyAlias(args.keyName)

            if (!checkKeyNotExists(args.keyName, alias, "generateSecureKey", invoke)) {
                return
            }

            // Check if Secure Element (StrongBox) is supported upfront
            val useSecureElement = isSecureElementSupported()
            val authMode = args.authMode ?: "pinOrBiometric"

            var keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

            var keyGenParameterSpec = buildKeyGenParameterSpec(alias, authMode, useSecureElement)

            try {
                keyPairGenerator.initialize(keyGenParameterSpec)
                keyPairGenerator.generateKeyPair()
            } catch (e: Exception) {
                // If Secure Element was requested but failed, fall back to regular hardware-backed storage
                if (useSecureElement) {
                    // Create a new KeyPairGenerator instance since it can't be reinitialized
                    keyPairGenerator =
                        KeyPairGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_EC,
                            "AndroidKeyStore",
                        )

                    keyGenParameterSpec = buildKeyGenParameterSpec(alias, authMode, false)

                    keyPairGenerator.initialize(keyGenParameterSpec)
                    keyPairGenerator.generateKeyPair()
                } else {
                    // Re-throw if StrongBox wasn't expected
                    throw e
                }
            }

            // Get the public key
            val entry =
                getKeyEntry(alias)
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
                val alias = aliases.nextElement() as String

                // Only process our keys (those with our prefix)
                if (!alias.startsWith(keyStoreAliasPrefix)) {
                    continue
                }

                // Extract key name from alias
                val keyName = alias.removePrefix(keyStoreAliasPrefix)

                // Apply key name filter if provided
                if (args.keyName != null && args.keyName != keyName) {
                    continue
                }

                // Get the public key
                val entry = getKeyEntry(alias) ?: continue
                val publicKeyBase64 = exportPublicKeyBase64(entry) ?: continue

                // Apply public key filter if provided
                if (args.publicKey != null && args.publicKey != publicKeyBase64) {
                    continue
                }

                // Determine if the key requires authentication
                val requiresAuth = keyRequiresAuthentication(alias)

                val keyInfo =
                    mutableMapOf<String, Any?>(
                        "keyName" to keyName,
                        "publicKey" to publicKeyBase64,
                    )
                if (requiresAuth != null) {
                    keyInfo["requiresAuthentication"] = requiresAuth
                }
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
        // Check the exception type and message for auth-related errors
        val message = e.message ?: ""
        return e.javaClass.name.contains("UserNotAuthenticated") ||
            message.contains("User not authenticated") ||
            message.contains("user not authenticated", ignoreCase = true) ||
            message.contains("KEY_USER_NOT_AUTHENTICATED") ||
            (e.cause?.message?.contains("user not authenticated", ignoreCase = true) == true)
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
        authInfo: KeyAuthInfo,
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

        // Build prompt info based on key's auth requirements
        val promptInfo = buildPromptInfoForKey(authInfo, "Sign with key: $keyName")

        // Show authentication UI with CryptoObject
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }

    @Command
    fun signWithKey(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(SignWithKeyArgs::class.java)
            val alias = getKeyAlias(args.keyName)

            if (!checkKeyExists(args.keyName, alias, "signWithKey", invoke)) {
                return
            }

            // Get the private key entry
            val entry =
                getKeyEntry(alias)
                    ?: run {
                        invoke.reject("Failed to get key entry")
                        return
                    }

            // Get auth info - if we can't determine, we'll find out when we try to sign
            val authInfo = getKeyAuthInfo(alias)

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

                    // Use detected auth info or default to PIN/biometric
                    val effectiveAuthInfo = authInfo ?: KeyAuthInfo(requiresAuthentication = true, isBiometricOnly = false)

                    // Show BiometricPrompt for authentication
                    signWithBiometricPrompt(entry, args.data, effectiveAuthInfo, args.keyName, invoke)
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
            val alias = getKeyAlias(args.keyName)

            if (!keyStore.containsAlias(alias)) {
                // Key doesn't exist, but we'll return success anyway (idempotent)
                val ret = JSObject()
                ret.put("success", true)
                invoke.resolve(ret)
                return
            }

            try {
                keyStore.deleteEntry(alias)
                val ret = JSObject()
                ret.put("success", true)
                invoke.resolve(ret)
            } catch (e: Exception) {
                val detailedMessage = "Failed to delete key: ${e.message}"
                val errorMessage = sanitizeError(detailedMessage, "Failed to delete key")
                Log.e(TAG, "deleteKey: $detailedMessage", e)
                invoke.reject(errorMessage)
            }
        } catch (e: Exception) {
            val detailedMessage = "Failed to delete key: ${e.message}"
            val errorMessage = sanitizeError(detailedMessage, "Failed to delete key")
            Log.e(TAG, "deleteKey: $detailedMessage", e)
            invoke.reject(errorMessage)
        }
    }
}
