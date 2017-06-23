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

/**
 * Convenient methods for generating or loading an AES key with size 256.
 * RSA is used as asymmetric algorithm for encryption and decryption of the AES key file.
 */
public class AESKeyGenerator {

    private static final String KEY_ALGORITHM_NAME = "AES";
    private static final int KEY_SIZE = 256;
    private static final String ASYM_KEY_ALGORITHM_NAME = "RSA";

    public static SymKey fromFile(final String encryptedSymKeyFilename,
                                  final String privateKeyFile,
                                  final String password) throws CryptoException {
        return SymKey.fromFile(encryptedSymKeyFilename, privateKeyFile, KEY_ALGORITHM_NAME, KEY_SIZE, ASYM_KEY_ALGORITHM_NAME, password);
    }

    public static SymKey fromFile(final String encryptedSymKeyFilename,
                                  final String privateKeyFilename) throws CryptoException {
        return SymKey.fromFile(encryptedSymKeyFilename, privateKeyFilename, KEY_ALGORITHM_NAME, KEY_SIZE, ASYM_KEY_ALGORITHM_NAME);
    }

    public static SymKey create(final String encryptedSymKeyFilename,
                                final String publicKeyFilename) throws CryptoException {
        return SymKey.create(encryptedSymKeyFilename, publicKeyFilename, KEY_ALGORITHM_NAME, KEY_SIZE, ASYM_KEY_ALGORITHM_NAME);
    }
}
