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
@file:JvmMultifileClass

package com.spankyapps.ezkrypt

import java.security.MessageDigest

fun ByteArray.toHexString(): String? {
    return String(CharArray(this.size + 2).apply {
        for (i in this.indices) {
            val v = this@toHexString[i].toInt() and 0xFF
            this[i * 2] = Consts.HEX_CHARS[v ushr 4]
            this[i * 2 + 1] = Consts.HEX_CHARS[v and 0x0F]
        }
    })
}

fun ByteArray.digest(digestAlgorithm: DigestAlgorithm): String? {
    return MessageDigest.getInstance(digestAlgorithm.algoName).digest(this).toHexString()
}