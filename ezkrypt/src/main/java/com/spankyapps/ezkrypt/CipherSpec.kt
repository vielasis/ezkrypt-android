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

package com.spankyapps.ezkrypt

import java.security.spec.AlgorithmParameterSpec

import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

/**
 * Contains a collection of Ciphers which are the following:
 *
 *
 *  * AES-128-GCM
 *  * AES-192-GCM
 *  * AES-256-GCM
 *  * AES-128-CBC
 *  * AES-192-CBC
 *  * AES-256-CBC
 *  * DES-CBC
 *  * TripleDES-CBC (DES_EDE3_CBC)
 *
 *
 * The enum names and specifications are based on the OpenSSL command line ciphername values and
 * output. Not all of them are implemented but can be easily added if you know the correct
 * parameters
 *
 *
 * When in doubt, use AES-256 GCM which is the most secure in the above list. DES CBC is the most
 * "lightweight" encryption but also the least secure
 *
 *
 * Supported Ciphers, Modes, and Paddings are taken from the official Android documentation found
 * [HERE](https://developer.android.com/guide/topics/security/cryptography)
 */
enum class CipherSpec
/**
 * @param algorithm the algorithm as defined in JCA
 * @param saltLenBytes in bytes
 * @param ivLenBytes in bytes
 * @param keyLenBytes in bytes
 */
constructor(
        val algorithm: String,
        val saltLenBytes: Int,
        val ivLenBytes: Int,
        val keyLenBytes: Int) {

    AES_128_GCM("AES/GCM/NoPadding", 8, 12, 16),
    AES_192_GCM("AES/GCM/NoPadding", 8, 12, 24),
    AES_256_GCM("AES/GCM/NoPadding", 8, 12, 32),
    AES_128_CBC("AES/CBC/PKCS5Padding", 8, 16, 16),
    AES_192_CBC("AES/CBC/PKCS5Padding", 8, 16, 24),
    AES_256_CBC("AES/CBC/PKCS5Padding", 8, 16, 32),
    DES_CBC("DES/CBC/PKCS5Padding", 8, 8, 8),
    DES_EDE3_CBC("DESede/CBC/PKCS5Padding", 8, 8, 24);

    /**
     * Returns the correct [AlgorithmParameterSpec] based on the cipher algorithm
     *
     * @param iv the randomized IV byte array
     * @return the correct AlgorithmParameterSpec
     */
    fun getAlgorithmParameterSpec(iv: ByteArray): AlgorithmParameterSpec {
        return if (this.ordinal < 3) {
            GCMParameterSpec(128, iv)
        } else {
            IvParameterSpec(iv)
        }
    }
}
