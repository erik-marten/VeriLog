/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.sign;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public final class BcPublicKeyLoader {
    private BcPublicKeyLoader() {}

    public static ECPublicKeyParameters fromSpkiDer(byte[] spkiDer) {
        try {
            var key = PublicKeyFactory.createKey(spkiDer);
            if (!(key instanceof ECPublicKeyParameters)) {
                throw new IllegalArgumentException("Not an EC public key");
            }
            return (ECPublicKeyParameters) key;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key", e);
        }
    }
}