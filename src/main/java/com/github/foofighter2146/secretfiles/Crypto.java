/*
 * Copyright 2017 Dr. Thomas Richert
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.foofighter2146.secretfiles;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * This one provides methods to encryptFile and decrypt data given by a String or by a file.
 */
public class Crypto {

    private final SymKey symKey;
    private final Cipher cipher;

    /**
     * Creates a Crypto instance and stores the symmetric key object.
     *
     * @param symKey A symmetric key
     * @throws CryptoException if enabling cipher instance fails
     */
    public Crypto(final SymKey symKey) throws CryptoException {
        this.symKey = symKey;
        try {
            this.cipher = Cipher.getInstance(symKey.getKeyAlgorithmName());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CryptoException("Cannot enable cipher instance for symmetric key", e);
        }
    }

    private void enableEncryption() throws CryptoException {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, symKey.getKeySpec());
        } catch (InvalidKeyException e) {
            throw new CryptoException("Cannot set encryption mode for cipher and symmetric key", e);
        }
    }

    private void enableDecryption() throws CryptoException {
        try {
            cipher.init(Cipher.DECRYPT_MODE, symKey.getKeySpec());
        } catch (InvalidKeyException e) {
            throw new CryptoException("Cannot set decryption mode for cipher and symmetric key", e);
        }
    }

    /**
     * Encrypts and then copies the contents of a given file.
     *
     * @param sourceFilename Name of source file
     * @param destFilename Name of destination file
     * @throws CryptoException if initialising encryption fails or an IO exception occurs
     */
    public void encryptFile(final String sourceFilename, final String destFilename) throws CryptoException {
        try {
            enableEncryption();

            try (final FileInputStream is = new FileInputStream(sourceFilename);
                 final CipherOutputStream os = new CipherOutputStream(new FileOutputStream(destFilename), cipher)) {
                copy(is, os);
            }

        } catch (IOException e) {
            throw new CryptoException(
                    "Cannot copy from decrypted source file '"
                            + sourceFilename + "' to enrypted destination file '" + destFilename + "'", e);
        }

    }

    /**
     * Decrypts and then copies the contents of a given file.
     *
     * @param sourceFilename Name of source file
     * @param destFilename Name of destination file
     * @throws CryptoException if initialising decryption fails or an IO exception occurs
     */
    public void decryptFile(final String sourceFilename, final String destFilename) throws CryptoException {
        try {
            enableDecryption();

            try (final CipherInputStream is = new CipherInputStream(new FileInputStream(sourceFilename), cipher);
                 final FileOutputStream os = new FileOutputStream(destFilename)) {
                copy(is, os);
            }

        } catch (IOException e) {
            throw new CryptoException(
                    "Cannot copy from encrypted source file '" + sourceFilename
                            + "' to derypted destination file '" + destFilename + "'", e);
        }
    }

    private void copy(final InputStream is, final OutputStream os) throws IOException {
        int i;
        byte[] b = new byte[1024];
        while((i = is.read(b)) != -1) {
            os.write(b, 0, i);
        }
    }


    /**
     * Encrypts a String and write the result into a file.
     *
     * @param data The data that should be encrypted
     * @param destFilename The name of the destination file
     * @param charset The Charset that should be used for encoding the data characters
     * @throws CryptoException if initialising encryption fails or an IO exception occurs
     */
    public void encrypt(final String data, final String destFilename, final Charset charset) throws CryptoException {
        try {
            final byte[] dataBytes = data.getBytes(charset);
            enableEncryption();

            try (final CipherOutputStream os = new CipherOutputStream(new FileOutputStream(destFilename), cipher)) {
                os.write(dataBytes);
            }

        } catch (IOException e) {
            throw new CryptoException("Cannot write encrypted data to file '" + destFilename + "'", e);
        }
    }

    /**
     * Encrypts a String and write the result into a file.
     * Default Encoding is UTF-8.
     *
     * @param data The data that should be encrypted
     * @param destFilename The name of the destination file
     * @throws CryptoException if UTF-8 is an invalid Charset, initialising encryption fails or an IO exception occurs
     */
    public void encrypt(final String data, final String destFilename) throws CryptoException {
        try {
            encrypt(data, destFilename, Charset.forName("UTF-8"));
        } catch (Exception e) {
            throw new CryptoException("UTF-8 is not a defined charset. Please use an explicit charsets.", e);
        }

    }

    /**
     * Read data from an encrypted file content and returns the decrypted data as String.
     *
     * @param sourceFilename The name of the source file
     * @param charset The Charset that should be used for encoding the data characters
     * @return The data as String
     * @throws CryptoException if initialising decryption fails or an IO exception occurs
     */
    public String decrypt(final String sourceFilename, final Charset charset) throws CryptoException {
        try {
            enableDecryption();

            final StringBuilder sb = new StringBuilder();
            try (final CipherInputStream is = new CipherInputStream(new FileInputStream(sourceFilename), cipher)) {

                while (true) {
                    final int b = is.read();
                    if (b == -1)
                        break;
                    sb.append((char) b);
                }
            }

            final String result = sb.toString();
            charset.encode(result);
            return result;

        } catch (IOException e) {
            throw new CryptoException("Cannot read encrypted data from file '" + sourceFilename + "'", e);
        }
    }

    /**
     * Read data from an encrypted file content and returns the decrypted data as String.
     * Default Encoding is UTF-8.
     *
     * @param sourceFilename The name of the source file
     * @return The data as String
     * @throws CryptoException UTF-8 is an invalid Charset, initialising decryption fails or an IO exception occurs
     */
    public String decrypt(final String sourceFilename) throws CryptoException {
        try {
            return decrypt(sourceFilename, Charset.forName("UTF-8"));
        } catch (Exception e) {
            throw new CryptoException("UTF-8 is not a defined charset. Please use an explicit charset.", e);
        }
    }
}
