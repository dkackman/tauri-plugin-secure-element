package app.tauri.plugin.secureelement

import android.app.Activity
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import app.tauri.plugin.Invoke
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.ArrayList

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
class SecureKeysPlugin(private val activity: Activity) : Plugin(activity) {
    private val keyStoreAliasPrefix = "secure_element_"
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private fun getKeyAlias(keyName: String): String {
        return "$keyStoreAliasPrefix$keyName"
    }

    @Command
    fun ping(invoke: Invoke) {
        val args = invoke.parseArgs(PingArgs::class.java)
        val ret = JSObject()
        ret.put("value", args.value ?: "")
        invoke.resolve(ret)
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

            // Check if key already exists
            if (keyStore.containsAlias(alias)) {
                invoke.reject("Key with name '${args.keyName}' already exists")
                return
            }

            // Try to use StrongBox if available, fall back to regular hardware-backed storage
            var keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            
            // First try with StrongBox if available
            var keyGenParameterSpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(true)
                .build()
            
            try {
                keyPairGenerator.initialize(keyGenParameterSpec)
                keyPairGenerator.generateKeyPair()
            } catch (e: Exception) {
                // StrongBox not available, fall back to regular hardware-backed storage
                // Create a new KeyPairGenerator instance since it can't be reinitialized
                keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
                )
                
                keyGenParameterSpec = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
                
                keyPairGenerator.initialize(keyGenParameterSpec)
                keyPairGenerator.generateKeyPair()
            }

            // Get the public key
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            val publicKey = entry?.certificate?.publicKey
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
            val keys = mutableListOf<JSObject>()

            // Iterate through all aliases in the keystore
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
                    ?: continue

                // Export public key in X.509 format (DER) and convert to base64
                val publicKeyBytes = publicKey.encoded
                val publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)

                // Apply public key filter if provided
                if (args.publicKey != null && args.publicKey != publicKeyBase64) {
                    continue
                }

                val keyInfo = JSObject()
                keyInfo.put("keyName", keyName)
                keyInfo.put("publicKey", publicKeyBase64)
                keys.add(keyInfo)
            }

            val ret = JSObject()
            ret.put("keys", ArrayList(keys))
            invoke.resolve(ret)
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

            // Check if key exists
            if (!keyStore.containsAlias(alias)) {
                invoke.reject("Key not found: ${args.keyName}")
                return
            }

            // Get the private key entry
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
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

            val ret = JSObject()
            ret.put("signature", signatureBytes)
            invoke.resolve(ret)
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
