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
package secretfiles;

import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Tests all components of this library in onne context.
 */
public class IntegrationTest {

    private final static String PATH = "src/test/resources/";
    private final static String PRIVATE_KEY_FILENAME = PATH + "int_private.der";
    private final static String PUBLIC_KEY_FILENAME = PATH + "int_public.der";
    private final static String AES_KEY_FILENAME = PATH + "int_aes.key";
    private final static String SOURCE = PATH + "source.txt";
    private final static String ENCRYPTED = PATH + "int_encrypted_file.txt";
    private final static String DECRYPTED = PATH + "int_decrypted.txt";
    private final static String ENCRYPTED_STRING = PATH + "int_encrypted_string.txt";

    @Test
    public void integrationTestFullRoundTrip() throws Exception {
        PPKGenerator.createRSA2048(PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME, "secret");

        SymKey symKey = AESKeyGenerator.create(AES_KEY_FILENAME, PUBLIC_KEY_FILENAME);
        SymKey symKey1 = AESKeyGenerator.fromFile(AES_KEY_FILENAME, PRIVATE_KEY_FILENAME, "secret");

        assertEquals(symKey.getKeySpec(), symKey1.getKeySpec());

        final Crypto crypto = new Crypto(symKey1);

        crypto.encryptFile(SOURCE, ENCRYPTED);
        crypto.decryptFile(ENCRYPTED, DECRYPTED);

        byte[] sourceContent = Files.readAllBytes(Paths.get(SOURCE));
        byte[] decryptedContent = Files.readAllBytes(Paths.get(DECRYPTED));

        assertTrue(Arrays.equals(sourceContent, decryptedContent));

        final Charset charset = Charset.forName("ISO-8859-1");
        final String data = "This is a small text only for unit testing.\nSome Special chars: öäüÖÜÄß!";

        crypto.encrypt(data, ENCRYPTED_STRING, charset);

        final String decryptedData = crypto.decrypt(ENCRYPTED_STRING, charset);

        assertEquals(data, decryptedData);
        
        // Cleanup
        Files.delete(Paths.get(PRIVATE_KEY_FILENAME));
        Files.delete(Paths.get(PUBLIC_KEY_FILENAME));
        Files.delete(Paths.get(AES_KEY_FILENAME));
        Files.delete(Paths.get(ENCRYPTED));
        Files.delete(Paths.get(DECRYPTED));
        Files.delete(Paths.get(ENCRYPTED_STRING));
    }
}
