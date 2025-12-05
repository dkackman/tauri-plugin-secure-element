package app.tauri.plugin.secureelement

import android.app.Activity
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
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
import java.util.HashMap
import org.json.JSONArray
import org.json.JSONObject

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
        val TAG = "SecureKeysPlugin"
        try {
            Log.d(TAG, "listKeys: Starting")
            val args = invoke.parseArgs(ListKeysArgs::class.java)
            Log.d(TAG, "listKeys: Parsed args - keyName=${args.keyName}, publicKey=${args.publicKey}")
            
            val keys = mutableListOf<JSObject>()
            Log.d(TAG, "listKeys: Created empty keys list, type=${keys.javaClass.name}")

            // Iterate through all aliases in the keystore
            val aliases = keyStore.aliases()
            var aliasCount = 0
            var processedCount = 0
            
            while (aliases.hasMoreElements()) {
                aliasCount++
                val alias = aliases.nextElement() as String
                Log.d(TAG, "listKeys: Processing alias #$aliasCount: $alias")

                // Only process our keys (those with our prefix)
                if (!alias.startsWith(keyStoreAliasPrefix)) {
                    Log.d(TAG, "listKeys: Skipping alias (no prefix match): $alias")
                    continue
                }

                // Extract key name from alias
                val keyName = alias.removePrefix(keyStoreAliasPrefix)
                Log.d(TAG, "listKeys: Extracted keyName: $keyName")

                // Apply key name filter if provided
                if (args.keyName != null && args.keyName != keyName) {
                    Log.d(TAG, "listKeys: Filtered out by keyName filter")
                    continue
                }

                // Get the public key
                val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                val publicKey = entry?.certificate?.publicKey
                if (publicKey == null) {
                    Log.d(TAG, "listKeys: Failed to get public key for alias: $alias")
                    continue
                }

                // Export public key in X.509 format (DER) and convert to base64
                val publicKeyBytes = publicKey.encoded
                val publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
                Log.d(TAG, "listKeys: Got public key (base64 length=${publicKeyBase64.length})")

                // Apply public key filter if provided
                if (args.publicKey != null && args.publicKey != publicKeyBase64) {
                    Log.d(TAG, "listKeys: Filtered out by publicKey filter")
                    continue
                }

                val keyInfo = JSObject()
                keyInfo.put("keyName", keyName)
                keyInfo.put("publicKey", publicKeyBase64)
                keys.add(keyInfo)
                processedCount++
                Log.d(TAG, "listKeys: Added key #$processedCount: $keyName")
            }

            Log.d(TAG, "listKeys: Finished iterating - total aliases=$aliasCount, processed keys=$processedCount")
            Log.d(TAG, "listKeys: keys.size=${keys.size}, keys.isEmpty=${keys.isEmpty()}")
            Log.d(TAG, "listKeys: keys type=${keys.javaClass.name}")

            val ret = JSObject()
            Log.d(TAG, "listKeys: Created ret JSObject")
            
            // Convert JSObject list to List<Map<String, String>> using JSONArray
            // JSONArray properly serializes empty arrays as [] not "[]"
            val jsonArray = JSONArray()
            for (keyObj in keys) {
                val jsonObj = JSONObject()
                jsonObj.put("keyName", keyObj.getString("keyName"))
                jsonObj.put("publicKey", keyObj.getString("publicKey"))
                jsonArray.put(jsonObj)
            }
            Log.d(TAG, "listKeys: Created JSONArray with ${jsonArray.length()} items")
            Log.d(TAG, "listKeys: JSONArray.toString(): ${jsonArray.toString()}")
            
            // Convert JSONArray to List<Map> for JSObject compatibility
            // JSObject.put() may not accept JSONArray directly, so convert to List
            val keysList = mutableListOf<Map<String, String>>()
            for (i in 0 until jsonArray.length()) {
                val jsonObj = jsonArray.getJSONObject(i)
                val keyMap = mapOf(
                    "keyName" to jsonObj.getString("keyName"),
                    "publicKey" to jsonObj.getString("publicKey")
                )
                keysList.add(keyMap)
            }
            Log.d(TAG, "listKeys: Created keysList (List<Map>) with ${keysList.size} items")
            Log.d(TAG, "listKeys: keysList type=${keysList.javaClass.name}")
            
            // Put the List<Map> - this should serialize correctly even when empty
            ret.put("keys", keysList)
            Log.d(TAG, "listKeys: Put keysList into ret JSObject")
            
            // Try to get the value back to see what was stored
            try {
                val storedValue = ret.get("keys")
                Log.d(TAG, "listKeys: Retrieved stored value type=${storedValue?.javaClass?.name}")
                Log.d(TAG, "listKeys: Retrieved stored value toString=${storedValue?.toString()}")
                if (storedValue != null) {
                    val storedIsList = storedValue is List<*>
                    val storedIsCollection = storedValue is Collection<*>
                    Log.d(TAG, "listKeys: Stored value is List: $storedIsList")
                    Log.d(TAG, "listKeys: Stored value is Collection: $storedIsCollection")
                    if (storedValue is Collection<*>) {
                        Log.d(TAG, "listKeys: Stored value size=${(storedValue as Collection<*>).size}")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "listKeys: Failed to retrieve stored value: ${e.message}", e)
            }
            
            // Log the entire JSObject as string
            try {
                val retString = ret.toString()
                Log.d(TAG, "listKeys: ret JSObject.toString(): $retString")
            } catch (e: Exception) {
                Log.e(TAG, "listKeys: Failed to convert ret to string: ${e.message}", e)
            }
            
            Log.d(TAG, "listKeys: About to resolve")
            invoke.resolve(ret)
            Log.d(TAG, "listKeys: Resolved successfully")
        } catch (e: Exception) {
            Log.e(TAG, "listKeys: Exception occurred: ${e.message}", e)
            Log.e(TAG, "listKeys: Exception stack trace", e)
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
