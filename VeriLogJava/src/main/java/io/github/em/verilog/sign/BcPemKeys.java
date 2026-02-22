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

import io.github.em.verilog.errors.VeriLogFormatException;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.StringReader;
import java.util.Objects;

public final class BcPemKeys {
    private BcPemKeys() {}

    public static byte[] readPkcs8PrivateKeyDer(String pem) throws VeriLogFormatException {
        Objects.requireNonNull(pem, "pem");

        try (PemReader r = new PemReader(new StringReader(pem))) {
            var obj = r.readPemObject();
            if (obj == null) throw new VeriLogFormatException("format.pem.empty");
            // Usually "PRIVATE KEY" for PKCS8
            return obj.getContent();
        } catch (IOException e) {
            throw new VeriLogFormatException("format.pem.read_failed", e);
        } catch (RuntimeException e) {
            // covers malformed base64 / invalid structure thrown inside bouncycastle reader
            throw new VeriLogFormatException("format.pem.read_failed", e);
        }
    }

    public static byte[] readSpkiPublicKeyDer(String pem) throws VeriLogFormatException {
        Objects.requireNonNull(pem, "pem");

        try (PemReader r = new PemReader(new StringReader(pem))) {
            var obj = r.readPemObject();
            if (obj == null) throw new VeriLogFormatException("format.pem.empty");
            // Usually "PUBLIC KEY" for SPKI
            return obj.getContent();
        } catch (IOException e) {
            throw new VeriLogFormatException("format.pem.read_failed", e);
        } catch (RuntimeException e) {
            throw new VeriLogFormatException("format.pem.read_failed", e);
        }
    }
}