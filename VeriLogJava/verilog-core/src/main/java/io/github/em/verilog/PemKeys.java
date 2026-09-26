/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog;

import io.github.em.verilog.errors.VeriLogCryptoException;
import io.github.em.verilog.errors.VeriLogFormatException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

public final class PemKeys {
    private PemKeys() {
    }

    public static PublicKey importEcPublicKeyFromPem(String pem) throws VeriLogFormatException, VeriLogCryptoException {
        Objects.requireNonNull(pem, "pem");

        try {
            String b64 = replace(pem);
            byte[] der = decode(b64);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            return KeyFactory.getInstance("EC").generatePublic(spec);

        } catch (VeriLogFormatException e) {
            throw e;
        } catch (NoSuchAlgorithmException e) {
            // should never happen on a normal JVM
            throw new VeriLogCryptoException("crypto.ec_keyfactory_unavailable", e);
        } catch (Exception e) {
            // invalid DER, wrong key type, etc.
            throw new VeriLogFormatException("format.pem.public_key_invalid", e);
        }
    }

    private static String replace(String pem) throws VeriLogFormatException {
        String b64 = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        if (b64.isEmpty()) {
            throw new VeriLogFormatException("format.pem.empty");
        }
        return b64;
    }

    private static byte[] decode(String b64) throws VeriLogFormatException {
        byte[] der;
        try {
            der = Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            throw new VeriLogFormatException("format.pem.base64_invalid", e);
        }
        return der;
    }
}