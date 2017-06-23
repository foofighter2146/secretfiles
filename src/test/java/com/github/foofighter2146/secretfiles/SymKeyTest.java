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

import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.assertEquals;

public final class SymKeyTest {

    private static final String TEMP_AES_KEY_FILE_PATH = "src/test/resources/test_aes_temp.key";

    @Test
    public final void testCreatingKeyAndCompareToLoadedKey() throws Exception {
        SymKey symKey = SymKey.create(
                TEMP_AES_KEY_FILE_PATH,
                "src/test/resources/test_public.der",
                "AES",
                256,
                "RSA");

        SymKey symKey1 = SymKey.fromFile(
                TEMP_AES_KEY_FILE_PATH,
                "src/test/resources/test_private_unprotected.der",
                "AES",
                256,
                "RSA");

        assertEquals(symKey.getKeySpec(), symKey1.getKeySpec());

        SymKey symKey2 = SymKey.fromFile(
                TEMP_AES_KEY_FILE_PATH,
                "src/test/resources/test_private_protected.der",
                "AES",
                256,
                "RSA",
                "secret");

        assertEquals(symKey.getKeySpec(), symKey2.getKeySpec());

        Files.delete(Paths.get(TEMP_AES_KEY_FILE_PATH));
    }


}
