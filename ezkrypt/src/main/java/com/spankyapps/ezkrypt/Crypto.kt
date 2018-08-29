/**
 * Copyright 2018 Krystian Viel Asis
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.spankyapps.ezkrypt

import android.util.Base64
import com.spankyapps.ezkrypt.Crypto.doCrypt
import com.spankyapps.ezkrypt.Utils.generateKey
import com.spankyapps.ezkrypt.Utils.generateRandomBytes
import java.io.*
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream

/**
 * Contains utility methods to aid in Encryption and Decryption of data in a very straightforward
 * API
 *
 *
 * The implementation is loosely based on the OpenSSL command line encryption. The difference is
 * we also prepend the IV and some metadata along with the salt and ciphertext.
 *
 *
 * **Sample Usage:**
 *
 * <pre>`// To Encrypt
 * byte[] plainData = ...
 * String password = "p4ssw0rd";
 * byte[] cipherData = Crypto.encrypt(plainData, password);
 *
 * // To Decrypt
 * byte[] cipherData = ...
 * String password = "p4ssw0rd";
 * byte[] plainData = Crypto.encrypt(cipherData, password);
`</pre> *
 *
 *
 * There is also a more general implementation [doCrypt] for more advanced users
 *
 *
 * Wrapping the encrypted data as [Base64] string if you need to use it in
 * SharedPreferences or process the data as a String
 */
object Crypto {

    // Integer.BYTES only available on API 24+
    private val INT_BYTES = Integer.SIZE / java.lang.Byte.SIZE
    private val DEFAULT_SIZE = 512
    /**
     * Encrypts the data using a desired CipherSpec. Setting it to *null* defaults to [CipherSpec.AES_256_GCM]
     *
     * @param cipherSpec the desired cipher spec
     * @param plainData the data to be encrypted
     * @param password the password
     * @return the encrypted data
     * @see CipherSpec
     */
    fun encrypt(cipherSpec: CipherSpec = CipherSpec.AES_256_GCM, plainData: ByteArray, password: String): ByteArray? {
        return ByteArrayOutputStream(DEFAULT_SIZE).let {
            try {
                doCrypt(Mode.ENCRYPT, cipherSpec, ByteArrayInputStream(plainData), it, password)
                return@let it
            } catch (e: IOException) {
                return@let null
            } catch (e: GeneralSecurityException) {
                return@let null
            }
        }?.toByteArray()
    }

    /**
     * Decrypts the data using the desired CipherSpec. Setting it to *null* defaults to [CipherSpec.AES_256_GCM]
     *
     * @param cipherSpec the desired cipher spec
     * @param cipherData the data to be decrypted
     * @param password the password
     * @return the decrypted data
     * @see CipherSpec
     */
    fun decrypt(cipherSpec: CipherSpec = CipherSpec.AES_256_GCM, cipherData: ByteArray, password: String): ByteArray? {
        return ByteArrayOutputStream(DEFAULT_SIZE).let {
            try {
                doCrypt(Mode.DECRYPT, cipherSpec, ByteArrayInputStream(cipherData), it, password)
                return@let it
            } catch (e: IOException) {
                return@let null
            } catch (e: GeneralSecurityException) {
                return@let null
            }
        }?.toByteArray()
    }

    /**
     * The most generic implementation. Use this when operating with streams/files. Note that the
     * ciphers used are **NOT** stream ciphers so out will only contain correct values after this
     * method call
     *
     * @param mode the Mode
     * @param cipherSpec the CipherSpec. If *null*, this will default to [CipherSpec.AES_256_GCM]
     * @param inStream the InputStream to be encrypted/decrypted
     * @param outStream the OutputStream of the decrypted/encrypted input
     * @param password the password
     * @throws IOException when any of the streams cannot be read or written
     * @throws GeneralSecurityException when any crpto related operations fail, the most usual case is
     * when a bad password is used in decryption
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    fun doCrypt(mode: Mode, cipherSpec: CipherSpec = CipherSpec.AES_256_GCM, inStream: InputStream, outStream: OutputStream, password: String) {
        var cos: CipherOutputStream? = null
        try {
            val salt: ByteArray
            val iv: ByteArray
            if (mode === Mode.ENCRYPT) {
                salt = generateRandomBytes(cipherSpec.saltLenBytes)
                iv = generateRandomBytes(cipherSpec.ivLenBytes)

                /*
                 * The lines below define our output format
                 * salt_len + salt[] + iv_len + iv[] + cipherData[]
                 * OpenSSL's implementation is:
                 * salt[] + cipherData[]
                 *
                 * We include the length metadata so we can reliably read an older implementation when we
                 * change iv/salt constants in CipherSpec except the keyLength - (which should not be
                 * changed anyway!)
                 */
                val header = ByteBuffer.allocate(INT_BYTES + salt.size + INT_BYTES + iv.size)
                header.putInt(salt.size).put(salt).putInt(iv.size).put(iv)

                outStream.write(header.array())
            } else {
                val saltMeta = ByteArray(INT_BYTES)
                val ivMeta = ByteArray(INT_BYTES)

                val saltMetaBytesRead = inStream.read(saltMeta)
                val saltBuff = ByteBuffer.wrap(saltMeta)
                val saltLen = saltBuff.int
                if (saltMetaBytesRead == -1 || saltLen < 0) {
                    throw GeneralSecurityException("Invalid salt length. bytes = $saltMetaBytesRead, len = $saltLen")
                }
                salt = ByteArray(saltLen)
                val saltBytesRead = inStream.read(salt, 0, saltLen)
                if (saltBytesRead == -1) {
                    throw GeneralSecurityException("Invalid salt. bytes = $saltBytesRead")
                }

                val ivMetaBytesRead = inStream.read(ivMeta)
                val ivBuff = ByteBuffer.wrap(ivMeta)
                val ivLen = ivBuff.int
                if (ivMetaBytesRead == -1 || ivLen < 0) {
                    throw GeneralSecurityException("Invalid iv length. bytes = $ivMetaBytesRead, len = $ivLen")
                }
                iv = ByteArray(ivLen)
                val ivBytesRead = inStream.read(iv, 0, ivLen)
                if (ivBytesRead < 0) {
                    throw GeneralSecurityException("Invalid iv. bytes = $ivBytesRead")
                }
            }

            val key = generateKey(password, cipherSpec.keyLenBytes, salt)
            val cipher = Cipher.getInstance(cipherSpec.algorithm)

            cipher.init(mode.mode, key, cipherSpec.getAlgorithmParameterSpec(iv))

            cos = CipherOutputStream(outStream, cipher)

            val buffer = ByteArray(4096)
            var bytesRead: Int = inStream.read(buffer, 0, buffer.size)
            while (bytesRead != -1) {
                cos.write(buffer, 0, bytesRead)
                bytesRead = inStream.read(buffer, 0, buffer.size)
            }
        } finally {
            cos?.apply {
                try {
                    close()
                } catch (e: IOException) {
                    e.printStackTrace()
                }
            }
        }
    }
}
