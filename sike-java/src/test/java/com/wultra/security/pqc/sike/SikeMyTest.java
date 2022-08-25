/*
 * Copyright 2020 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.wultra.security.pqc.sike;

import com.wultra.security.pqc.sike.crypto.KeyGenerator;
import com.wultra.security.pqc.sike.crypto.RandomGenerator;
import com.wultra.security.pqc.sike.crypto.Sike;
import com.wultra.security.pqc.sike.kat.util.CrtDrbgRandom;
import com.wultra.security.pqc.sike.model.*;
import com.wultra.security.pqc.sike.param.*;
import com.wultra.security.pqc.sike.util.OctetEncoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SikeMyTest {

    private static final String SEED = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testCCA() throws GeneralSecurityException {
        System.out.println("----------------------------------------");
        for (SikeParam sikeParam : new SikeParam[]{new SikeParamP434(ImplementationType.OPTIMIZED),
                                                    new SikeParamP503(ImplementationType.OPTIMIZED),
                                                    new SikeParamP610(ImplementationType.OPTIMIZED),
                                                    new SikeParamP751(ImplementationType.OPTIMIZED)}) {
            System.out.println("param: " + sikeParam);
            byte[] seedBytes = Hex.decode(SEED);
            CrtDrbgRandom drbgRandom = new CrtDrbgRandom(seedBytes);
            KeyGenerator keyGenerator = new KeyGenerator(sikeParam, new RandomGenerator(drbgRandom));

            KeyPair keyPair = keyGenerator.generateKeyPair(Party.BOB);
            SidhPrivateKey priv = (SidhPrivateKey) keyPair.getPrivate();
            SidhPublicKey pub = (SidhPublicKey) keyPair.getPublic();

            Sike sike = new Sike(sikeParam, drbgRandom);
            EncapsulationResult encapsulationResult = sike.encapsulate(keyPair.getPublic());
            EncryptedMessage encrypted = encapsulationResult.getEncryptedMessage();
            System.out.println("Alice's shared secret: " + new String(Base64.encode(encapsulationResult.getSecret())));

            byte[] secretDecaps = sike.decapsulate(keyPair.getPrivate(), keyPair.getPublic(), encrypted);
            System.out.println("Bob's shared secret:   " + new String(Base64.encode(secretDecaps)));

            boolean match = Arrays.equals(encapsulationResult.getSecret(), secretDecaps);
            System.out.println("Shared secrets match: " + match);
            assertTrue(match, "Decapsulation failed");

            byte[] encEncrypted = encrypted.getEncoded();
            byte[] encEncryptedCopy = encEncrypted.clone();

            for (int p = 0; p < encEncryptedCopy.length; p++) {
                for (int b = 0; b < 8; b++) {
                    encEncryptedCopy[p] = (byte) (encEncrypted[p] ^ (1 << b));
                    EncryptedMessage encryptedMod = new EncryptedMessage(sikeParam, encEncryptedCopy);
                    byte[] secretDecapsMod = sike.decapsulate(keyPair.getPrivate(), keyPair.getPublic(), encryptedMod);
                    match = Arrays.equals(encapsulationResult.getSecret(), secretDecapsMod);
                    assertFalse(match, "CCA issue at " + p + ":" + b);
                }
                encEncryptedCopy[p] = encEncrypted[p];
            }
        }
    }

}
