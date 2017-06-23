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
package com.fewdata.secretfiles;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * This class provides static methods for generating a private/public key pair.
 * The private key is PKCS#8 and must be protected by a password.
 */
public final class PPKGenerator {

    /**
     * Creates a private/public key pair.
     *
     * @param privateKeyFilename The name of the file that contains the the private key
     * @param publicKeyFilename The name of the file that contains the public key
     * @param password The password to protect the private key
     * @param algorithmName The name of the key generation algorithm, e.g. RSA
     * @param keySize The bit size of the key, e.g. 2048
     * @throws CryptoException if something goes wrong by generating the key or storing the key into files
     */
    public static void create(final String privateKeyFilename,
                              final String publicKeyFilename,
                              final String password,
                              final String algorithmName,
                              final int keySize) throws CryptoException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithmName);
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair = keyPairGenerator.genKeyPair();

            // extract the encoded private key, this is an unencrypted PKCS#8 private key
            final byte[] encodedPrivateKey = keyPair.getPrivate().getEncoded();

            // We must use a PasswordBasedEncryption algorithm in order to encrypt the private key,
            // you may use any common algorithm supported by openssl, you can check them in the openssl
            // documentation http://www.openssl.org/docs/apps/pkcs8.html
            final String pbeAlgorithmName = "PBEWithSHA1AndDESede";

            final int count = 20; //hash iteration count
            final SecureRandom random = new SecureRandom();
            final byte[] salt = new byte[8];
            random.nextBytes(salt);

            // Create PBE parameter set
            final PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);
            final PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            final SecretKeyFactory keyFac = SecretKeyFactory.getInstance(pbeAlgorithmName);
            final SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

            final Cipher pbeCipher = Cipher.getInstance(pbeAlgorithmName);

            // Initialize PBE Cipher with key and parameters
            pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

            // Encrypt the encoded Private Key with the PBE key
            final byte[] cipherText = pbeCipher.doFinal(encodedPrivateKey);

            // Now construct PKCS#8 EncryptedPrivateKeyInfo object
            final AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(pbeAlgorithmName);
            algorithmParameters.init(pbeParamSpec);
            final EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(algorithmParameters, cipherText);

            // Now write it to disk
            try (final FileOutputStream out = new FileOutputStream(privateKeyFilename)) {
                out.write(encryptedPrivateKeyInfo.getEncoded());
            }

            // Don't forget the public key
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
            try (final FileOutputStream out = new FileOutputStream(publicKeyFilename)) {
                out.write(x509EncodedKeySpec.getEncoded());
            }

        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException("Error while generating private/public key pair", e);
        }

    }

    /**
     * Creates a private/public key pair wirh RSA algorithm and key size of 2048 bits.
     *
     * @param privateKeyFilename The name of the file that contains the the private key
     * @param publicKeyFilename The name of the file that contains the public key
     * @param password The password to protect the private key
     * @throws CryptoException if something goes wrong by generating the key or storing the key into files
     */
    public static void createRSA2048(final String privateKeyFilename,
                                     final String publicKeyFilename,
                                     final String password) throws CryptoException {
        create(privateKeyFilename, publicKeyFilename, password, "RSA", 2048);
    }
}
