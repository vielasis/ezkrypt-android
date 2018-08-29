/**
 * Copyright 2018 Krystian Viel Asis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

@file:JvmName("CryptoUtils")

package com.spankyapps.ezkrypt

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

fun ByteArray.toHexString(): String? {
    return String(CharArray(this.size + 2).apply {
        for (i in this.indices) {
            val v = this@toHexString[i].toInt() and 0xFF
            this[i * 2] = Utils.HEX_CHARS[v ushr 4]
            this[i * 2 + 1] = Utils.HEX_CHARS[v and 0x0F]
        }
    })
}

fun ByteArray.digest(digestAlgorithm: DigestAlgorithm): String? {
    return MessageDigest.getInstance(digestAlgorithm.algoName).digest(this).toHexString()
}

object Utils {
    val KEY_DERIVATION_ITERATIONS = 1024
    val KEY_FACTORY_ALGO = "PBKDF2WithHmacSHA1"
    val HEX_CHARS = "0123456789ABCDEF".toCharArray()

    fun generateKey(password: String, keyLengthBytes: Int, salt: ByteArray): SecretKey {
        return SecretKeyFactory.getInstance(KEY_FACTORY_ALGO).let {
            val keySpec = PBEKeySpec(password.toCharArray(), salt, KEY_DERIVATION_ITERATIONS, keyLengthBytes * java.lang.Byte.SIZE)
            it.generateSecret(keySpec)
        }
    }

    fun generateRandomBytes(length: Int): ByteArray {
        return ByteArray(length).apply {
            SecureRandom().nextBytes(this)
        }
    }
}