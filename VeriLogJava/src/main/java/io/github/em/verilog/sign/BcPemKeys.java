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
import org.bouncycastle.util.io.pem.PemReader;

import java.io.StringReader;

public final class BcPemKeys {
    private BcPemKeys() {}

    public static byte[] readPkcs8PrivateKeyDer(String pem) {
        try (PemReader r = new PemReader(new StringReader(pem))) {
            var obj = r.readPemObject();
            if (obj == null) throw new IllegalArgumentException("Empty PEM");
            // Usually "PRIVATE KEY" for PKCS8
            return obj.getContent();
        } catch (Exception e) {
            throw new RuntimeException("Failed to read private key PEM", e);
        }
    }

    public static byte[] readSpkiPublicKeyDer(String pem) {
        try (PemReader r = new PemReader(new StringReader(pem))) {
            var obj = r.readPemObject();
            if (obj == null) throw new IllegalArgumentException("Empty PEM");
            // Usually "PUBLIC KEY" for SPKI
            return obj.getContent();
        } catch (Exception e) {
            throw new RuntimeException("Failed to read public key PEM", e);
        }
    }
}