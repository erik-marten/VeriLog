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
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.util.Objects;

public final class BcPublicKeyLoader {
    private BcPublicKeyLoader() {
    }

    public static ECPublicKeyParameters fromSpkiDer(byte[] spkiDer) throws VeriLogFormatException {
        Objects.requireNonNull(spkiDer, "spkiDer");

        try {
            var key = PublicKeyFactory.createKey(spkiDer);
            if (!(key instanceof ECPublicKeyParameters)) {
                throw new VeriLogFormatException("format.key.not_ec_public");
            }
            return (ECPublicKeyParameters) key;
        } catch (VeriLogFormatException e) {
            throw e;
        } catch (Exception e) {
            // bad DER / unsupported algorithm / malformed data
            throw new VeriLogFormatException("format.key.spki_invalid", e);
        }
    }
}