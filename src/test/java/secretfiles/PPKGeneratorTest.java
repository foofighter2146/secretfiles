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

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.assertEquals;

public class PPKGeneratorTest {

    private final static String PATH = "src/test/resources/";
    private final static String PRIVATE_KEY_FILENAME = PATH + "ppkgen_private.der";
    private final static String PUBLIC_KEY_FILENAME = PATH + "ppkgen_public.der";
    private final static String AES_KEY_FILENAME = PATH + "ppkgen_aes.key";

    @Test
    public void testGenerateKeyPairAndUseItForSymKeyEncryption() throws Exception {

        PPKGenerator.createRSA2048(PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME, "secret");

        SymKey symKey = AESKeyGenerator.create(AES_KEY_FILENAME, PUBLIC_KEY_FILENAME);
        SymKey symKey1 = AESKeyGenerator.fromFile(AES_KEY_FILENAME, PRIVATE_KEY_FILENAME, "secret");

        assertEquals(symKey.getKeySpec(), symKey1.getKeySpec());

        // Cleanup
        Files.delete(Paths.get(PRIVATE_KEY_FILENAME));
        Files.delete(Paths.get(PUBLIC_KEY_FILENAME));
        Files.delete(Paths.get(AES_KEY_FILENAME));
    }

}
