package app.tauri.plugin.secureelement

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec

@InvokeArg
class PingArgs {
    var value: String? = null
}

@InvokeArg
class GenerateSecureKeyArgs {
    var keyName: String = ""
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

    private val keyStoreAliasPrefix = "secure_element_"
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun getKeyAlias(keyName: String): String = "$keyStoreAliasPrefix$keyName"

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
     * This checks if keys can be stored in hardware-backed storage (TEE) even without StrongBox.
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
            val errorMessage = "Failed to check Secure Element support: ${e.message ?: e.javaClass.simpleName}"
            invoke.reject(errorMessage)
        }
    }

    @Command
    fun generateSecureKey(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(GenerateSecureKeyArgs::class.java)

            if (args.keyName.isBlank()) {
                invoke.reject("Key name cannot be empty")
                return
            }

            val alias = getKeyAlias(args.keyName)

            if (keyStore.containsAlias(alias)) {
                invoke.reject("Key with name '${args.keyName}' already exists")
                return
            }

            // Check if Secure Element (StrongBox) is supported upfront
            val useSecureElement = isSecureElementSupported()

            var keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

            var keyGenParameterSpec =
                KeyGenParameterSpec
                    .Builder(
                        alias,
                        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                    ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .apply {
                        // Only set StrongBox if Secure Element is supported
                        if (useSecureElement) {
                            setIsStrongBoxBacked(true)
                        }
                    }.build()

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

                    keyGenParameterSpec =
                        KeyGenParameterSpec
                            .Builder(
                                alias,
                                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                            ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .build()

                    keyPairGenerator.initialize(keyGenParameterSpec)
                    keyPairGenerator.generateKeyPair()
                } else {
                    // Re-throw if StrongBox wasn't expected
                    throw e
                }
            }

            // Get the public key
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            val publicKey =
                entry?.certificate?.publicKey
                    ?: throw Exception("Failed to get public key after key generation")

            // Export public key in X.509 format (DER) and convert to base64
            val publicKeyBytes = publicKey.encoded
            val publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)

            val ret = JSObject()
            ret.put("publicKey", publicKeyBase64)
            ret.put("keyName", args.keyName)
            invoke.resolve(ret)
        } catch (e: Exception) {
            invoke.reject("Failed to create key: ${e.message ?: e.javaClass.simpleName}")
        }
    }

    @Command
    fun listKeys(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(ListKeysArgs::class.java)

            val keys = mutableListOf<Map<String, String>>()

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
                val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                val publicKey = entry?.certificate?.publicKey
                if (publicKey == null) {
                    continue
                }

                // Export public key in X.509 format (DER) and convert to base64
                val publicKeyBytes = publicKey.encoded
                val publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)

                // Apply public key filter if provided
                if (args.publicKey != null && args.publicKey != publicKeyBase64) {
                    continue
                }

                val keyInfo = mapOf("keyName" to keyName, "publicKey" to publicKeyBase64)
                keys.add(keyInfo)
            }

            // Use resolveObject with Map to ensure proper JSON serialization
            val ret = mapOf("keys" to keys)
            invoke.resolveObject(ret)
        } catch (e: Exception) {
            invoke.reject("Failed to list keys: ${e.message}")
        }
    }

    @Command
    fun signWithKey(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(SignWithKeyArgs::class.java)

            if (args.keyName.isBlank()) {
                invoke.reject("Key name cannot be empty")
                return
            }

            val alias = getKeyAlias(args.keyName)

            if (!keyStore.containsAlias(alias)) {
                invoke.reject("Key not found: ${args.keyName}")
                return
            }

            // Get the private key entry
            val entry =
                keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                    ?: throw Exception("Failed to get key entry")

            // Sign the data using ECDSA with SHA-256
            // Note: Android's SHA256withECDSA hashes the data internally,
            // while iOS hashes first then signs the digest.
            // Both approaches produce valid ECDSA signatures, though the encoding
            // format may differ (DER vs X962). For verification purposes, both are valid.
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(entry.privateKey)
            signature.update(args.data)
            val signatureBytes = signature.sign()

            // Convert ByteArray to List<Int> (unsigned bytes 0-255) for proper JSON serialization
            val signatureArray = signatureBytes.map { it.toInt() and 0xFF }
            val ret = mapOf("signature" to signatureArray)
            invoke.resolveObject(ret)
        } catch (e: Exception) {
            invoke.reject("Failed to sign: ${e.message}")
        }
    }

    @Command
    fun deleteKey(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(DeleteKeyArgs::class.java)

            if (args.keyName.isBlank()) {
                invoke.reject("Key name cannot be empty")
                return
            }

            val alias = getKeyAlias(args.keyName)

            // Check if key exists
            if (!keyStore.containsAlias(alias)) {
                // Key doesn't exist, but we'll return success anyway (idempotent)
                val ret = JSObject()
                ret.put("success", true)
                invoke.resolve(ret)
                return
            }

            // Delete the key
            keyStore.deleteEntry(alias)

            val ret = JSObject()
            ret.put("success", true)
            invoke.resolve(ret)
        } catch (e: Exception) {
            invoke.reject("Failed to delete key: ${e.message}")
        }
    }
}
