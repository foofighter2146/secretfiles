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

import org.junit.*;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import static org.junit.Assert.*;

public final class CryptoTest {

    private final static String PATH = "src/test/resources/";
    private final static String SOURCE = PATH + "source.txt";
    private final static String ENCRYPTED = PATH + "encrypted_file.txt";
    private final static String DECRYPTED = PATH + "decrypted.txt";
    private final static String ENCRYPTED_STRING = PATH + "encrypted_string.txt";

    private static SymKey symKey;

    @BeforeClass
    public static void init() throws Exception {
        symKey = AESKeyGenerator.create(
                PATH + "test_aes.key",
                PATH + "test_public.der");
    }

    @AfterClass
    public static void cleanup() throws Exception {
        Files.delete(Paths.get(PATH + "test_aes.key"));
    }

    @Test
    public final void encryptAndDecryptAndCompareFile() throws Exception {

        final Crypto crypto = new Crypto(symKey);

        crypto.encryptFile(SOURCE, ENCRYPTED);
        crypto.decryptFile(ENCRYPTED, DECRYPTED);

        byte[] sourceContent = Files.readAllBytes(Paths.get(SOURCE));
        byte[] decryptedContent = Files.readAllBytes(Paths.get(DECRYPTED));

        assertTrue(Arrays.equals(sourceContent, decryptedContent));

        // Cleanup
        Files.delete(Paths.get(ENCRYPTED));
        Files.delete(Paths.get(DECRYPTED));
    }

    @Test
    public final void encryptAndDecryptAndCompareString() throws Exception {

        final Charset charset = Charset.forName("ISO-8859-1");
        final String content = "This is a small text only for unit testing.\nSome Special chars: öäüÖÜÄß!";

        final Crypto crypto = new Crypto(symKey);

        crypto.encrypt(content, ENCRYPTED_STRING, charset);

        final String decryptedContent = crypto.decrypt(ENCRYPTED_STRING, charset);

        assertEquals(content, decryptedContent);

        // Cleanup
        Files.delete(Paths.get(ENCRYPTED_STRING));
    }

    @Test
    public final void encryptAndDecryptAndCompareStringWithUTF8() throws Exception {

        final String content = "This tst string contains only utf-8 characters!";

        final Crypto crypto = new Crypto(symKey);

        crypto.encrypt(content, ENCRYPTED_STRING);

        final String decryptedContent = crypto.decrypt(ENCRYPTED_STRING);

        assertEquals(content, decryptedContent);

        // Cleanup
        Files.delete(Paths.get(ENCRYPTED_STRING));
    }
}
