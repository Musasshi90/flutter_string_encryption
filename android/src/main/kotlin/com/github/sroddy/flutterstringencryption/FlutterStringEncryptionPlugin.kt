package com.github.sroddy.flutterstringencryption

import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.PluginRegistry
import io.flutter.embedding.engine.plugins.FlutterPlugin
import com.tozny.crypto.android.AesCbcWithIntegrity.*
import io.flutter.plugin.common.EventChannel
import java.security.GeneralSecurityException

class FlutterStringEncryptionPlugin() : MethodChannel.MethodCallHandler, FlutterPlugin {
    private val initializationLock = Any()
    private var flutterChannel: MethodChannel? = null

    override fun onAttachedToEngine(p0: FlutterPlugin.FlutterPluginBinding) {
        synchronized(initializationLock) {
            if (flutterChannel != null) {
                return
            }
            flutterChannel = MethodChannel(p0.getBinaryMessenger(), "flutter_string_encryption")
            flutterChannel!!.setMethodCallHandler(this)
        }
    }

    override fun onDetachedFromEngine(p0: FlutterPlugin.FlutterPluginBinding) {
        if (flutterChannel != null) {
            flutterChannel!!.setMethodCallHandler(null)
            flutterChannel = null
        }
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "decrypt" -> {
                val data = call.argument<String>("data")
                val keyString = call.argument<String>("key")

                val civ = CipherTextIvMac(data)
                try {
                    val decrypted = decryptString(civ, keys(keyString))
                    result.success(decrypted)
                } catch (e: GeneralSecurityException) {
                    print(e)
                    result.error("mac_mismatch", "Mac don't match", null)
                }
            }
            "encrypt" -> {
                val string = call.argument<String>("string")
                val keyString = call.argument<String>("key")

                val encrypted = encrypt(string, keys(keyString))

                result.success(encrypted.toString())
            }
            "generate_random_key" -> {
                val key = generateKey()
                val keyString = keyString(key)

                result.success(keyString)
            }
            "generate_salt" -> {
                val salt = generateSalt()
                val base64Salt = saltString(salt)

                result.success(base64Salt)
            }
            "generate_key_from_password" -> {
                val password = call.argument<String>("password")
                val salt = call.argument<String>("salt")

                val key = generateKeyFromPassword(password, salt)
                val keyString = keyString(key)

                result.success(keyString)
            }
            else -> result.notImplemented()
        }
    }
}
