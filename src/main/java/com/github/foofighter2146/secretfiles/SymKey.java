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

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Holds an immutable symmetric key. It is not possible to create an instance of this
 * class directly. Instead use the factory methods that either creates a new key and store
 * it encrypted with a public key, or load the encrypted key from a file end decrypt it with a
 * private key.
 */
public final class SymKey {

    private byte[] key;
    private SecretKeySpec keySpec;

    private String keyAlgorithmName;
    private int keySize;
    private String asymKeyAlgorithmName;

    /**
     * @return Encoded key as byte array.
     */
    public byte[] getKey() {
        return key;
    }

    /**
     * @return The key specification.
     */
    public SecretKeySpec getKeySpec() {
        return keySpec;
    }


    /**
     * @return The name of the algorithm that is used for this symmetric key.
     */
    public String getKeyAlgorithmName() {
        return keyAlgorithmName;
    }

    /**
     * @return Size of this key, e.g. 256
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * @return Name of the algorithm that is used for symmetric key generation here, e.g. AES.
     */
    public String getAsymKeyAlgorithmName() {
        return asymKeyAlgorithmName;
    }

    /**
     * Loads an encrypted symmetric key from a file and decrypt it with a private key
     * that is protected by a password.
     *
     * @param encryptedSymKeyFilename The name of the file that holds the symmetric key
     * @param privateKeyFilename The name of the file that holds the protected private key
     * @param keyAlgorithmName The name of the symmetric algorithm, e.g. AES
     * @param keySize The number of bytes of the symmetric key, e.g 256
     * @param asymKeyAlgorithmName The name of the asymmetric algorithm, e.g. RSA
     * @param password Password to get access to the protected private key
     * @return A new immutable symmetric key
     * @throws CryptoException if a security exception or an IO exception occurs
     */
    public static SymKey fromFile(final String encryptedSymKeyFilename,
                                  final String privateKeyFilename,
                                  final String keyAlgorithmName,
                                  final int keySize,
                                  final String asymKeyAlgorithmName,
                                  final String password) throws CryptoException {
        try {
            // read private key to be used to decrypt the AES key
            final byte[] encodedKey = readAllBytes(privateKeyFilename);

            // prepare password
            final PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());

            // decrypt private key file
            final EncryptedPrivateKeyInfo encryptPKInfo = new EncryptedPrivateKeyInfo(encodedKey);
            final Cipher cipher = Cipher.getInstance(encryptPKInfo.getAlgName());
            final SecretKeyFactory secFac = SecretKeyFactory.getInstance(encryptPKInfo.getAlgName());
            final Key pbeKey = secFac.generateSecret(pbeKeySpec);
            final AlgorithmParameters algParams = encryptPKInfo.getAlgParameters();
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
            final KeySpec privateKeySpec = encryptPKInfo.getKeySpec(cipher);

            return readFromFile(encryptedSymKeyFilename, privateKeySpec, keyAlgorithmName, keySize, asymKeyAlgorithmName);

        } catch (IOException | GeneralSecurityException e) {
            throw new CryptoException("Error while loading an encrypted symmetric key and decrypting by protected private key", e);
        }
    }

    /**
     * Loads an encrypted symmetric key from a file and decrypt it with a unprotected private key.
     *
     * @param encryptedSymKeyFilename The name of the file that holds the symmetric key
     * @param privateKeyFilename The name of the file that holds the unprotected private key
     * @param keyAlgorithmName The name of the symmetric algorithm, e.g. AES
     * @param keySize The number of bytes of the symmetric key, e.g 256
     * @param asymKeyAlgorithmName The name of the asymmetric algorithm, e.g. RSA
     * @return A new immutable symmetric key
     * @throws CryptoException if a security exception or an IO exception occurs
     */
    public static SymKey fromFile(final String encryptedSymKeyFilename,
                                  final String privateKeyFilename,
                                  final String keyAlgorithmName,
                                  final int keySize,
                                  final String asymKeyAlgorithmName) throws CryptoException {
        try {

            // read private key to be used to decrypt the AES key
            final byte[] encodedKey = readAllBytes(privateKeyFilename);
            // create private key
            final PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);

            return readFromFile(encryptedSymKeyFilename, privateKeySpec, keyAlgorithmName, keySize, asymKeyAlgorithmName);

        } catch (IOException e) {
            throw new CryptoException("Error while loading an encrypted symmetric key and decrypting by private key", e);
        }
    }

    private static SymKey readFromFile(final String encryptedSymKeyFilename,
                                       final KeySpec privateKeySpec,
                                       final String keyAlgorithmName,
                                       final int keySize,
                                       final String asymKeyAlgorithmName) throws CryptoException {
        try {

            KeyFactory kf = KeyFactory.getInstance(asymKeyAlgorithmName);
            PrivateKey pk = kf.generatePrivate(privateKeySpec);

            final Cipher pkCipher = Cipher.getInstance(asymKeyAlgorithmName);
            pkCipher.init(Cipher.DECRYPT_MODE, pk);

            final byte[] keyArray = new byte[keySize / 8];

            try (final CipherInputStream is = new CipherInputStream(new FileInputStream(encryptedSymKeyFilename), pkCipher)) {
                is.read(keyArray);
            }

            return new SymKey(keyArray, keyAlgorithmName, keySize, asymKeyAlgorithmName);

        } catch (IOException | GeneralSecurityException e) {
            throw new CryptoException("Error while loading an encrypted symmetric key an decrypting by private key", e);
        }
    }

    /**
     * Creates a new symmetric key an stores an encrypted version into an file.
     * A public key from a file is used for encryption.
     * 
     * @param encryptedSymKeyFilename The name of the file in that the symmetric key sould be stored
     * @param publicKeyFilename The name of the file that holds the public key
     * @param keyAlgorithmName The name of the symmetric algorithm, e.g. AES
     * @param keySize The number of bytes of the symmetric key, e.g 256
     * @param asymKeyAlgorithmName The name of the asymmetric algorithm, e.g. RSA
     * @return A new immutable symmetric key
     * @throws CryptoException if a security exception or an IO exception occurs
     */
    public static SymKey create(final String encryptedSymKeyFilename,
                                final String publicKeyFilename,
                                final String keyAlgorithmName,
                                final int keySize,
                                final String asymKeyAlgorithmName) throws CryptoException {
        try {

            // Creates a new symKey instance
            final SymKey symKey = createKey(keyAlgorithmName, keySize, asymKeyAlgorithmName);

            // Reads public key from file
            final byte[] encodedKey = readAllBytes(publicKeyFilename);

            // create public key
            final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
            final KeyFactory kf = KeyFactory.getInstance(asymKeyAlgorithmName);
            final PublicKey pk = kf.generatePublic(publicKeySpec);

            // write symmetric key
            final Cipher pkCipher = Cipher.getInstance(asymKeyAlgorithmName);
            pkCipher.init(Cipher.ENCRYPT_MODE, pk);

            try (final CipherOutputStream os = new CipherOutputStream(new FileOutputStream(encryptedSymKeyFilename), pkCipher)) {
                os.write(symKey.getKey());
            }
            return symKey;

        } catch (IOException | GeneralSecurityException e) {
            throw new CryptoException("Error while creating an encrypted symmetric key and storing it into a file", e);
        }
    }

    private static SymKey createKey(final String keyAlgorithmName,
                                    final int keySize,
                                    final String asymKeyAlgorithmName) throws CryptoException {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance(keyAlgorithmName);
            kgen.init(keySize);
            SecretKey key = kgen.generateKey();
            return new SymKey(key.getEncoded(), keyAlgorithmName, keySize, asymKeyAlgorithmName);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Error while generating symmetric key", e);
        }
    }

    private SymKey(final byte[] key, final String keyAlgorithmName, final int keySize, final String asymKeyAlgorithmName) {
        this.key = key;
        this.keySpec = new SecretKeySpec(key, keyAlgorithmName);
        this.keyAlgorithmName = keyAlgorithmName;
        this.keySize = keySize;
        this.asymKeyAlgorithmName = asymKeyAlgorithmName;
    }

    private static byte [] readAllBytes(final String filename) throws IOException {
        return Files.readAllBytes(Paths.get(filename));
    }
}
