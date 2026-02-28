/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.reader;

import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.EcdsaSigCodec;
import io.github.em.verilog.errors.VeriLogCryptoException;
import io.github.em.verilog.errors.VeriLogFormatException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Objects;

public final class BcEcdsaVerifier {
    static org.bouncycastle.crypto.signers.DSAEncoding dsaEncoding = StandardDSAEncoding.INSTANCE;

    private BcEcdsaVerifier() {
    }

    public static boolean verifyEntryHashSig(
            ECPublicKeyParameters pub,
            byte[] entryHash32,
            byte[] sigRaw64
    ) throws VeriLogCryptoException {

        Objects.requireNonNull(pub, "pub must not be null");

        if (entryHash32 == null || entryHash32.length != 32)
            throw new IllegalArgumentException("entryHash must be 32 bytes");

        if (sigRaw64 == null || sigRaw64.length != 64)
            throw new IllegalArgumentException("sig must be 64 bytes");

        // must match signer: sign SHA256(entryHashBytes)
        final byte[] digest;
        try {
            digest = CryptoUtil.sha256(entryHash32);
        } catch (RuntimeException e) {
            // sha256 should never fail- if it does, it's a crypto/runtime problem
            throw new VeriLogCryptoException("crypto.hash_failed", e);
        }

        final byte[] der;
        try {
            der = EcdsaSigCodec.rawToDer(sigRaw64);
        } catch (IllegalArgumentException | VeriLogFormatException e) {
            // Malformed signature input; treat as invalid signature (untrusted input)
            return false;
        } catch (RuntimeException e) {
            // Unexpected internal/runtime failure
            throw new VeriLogCryptoException("crypto.sig_encode_failed", e);
        }

        final BigInteger[] rs;
        try {
            rs = dsaEncoding.decode(pub.getParameters().getN(), der);
        } catch (IOException | IllegalArgumentException e) {
            // Malformed DER signature
            return false;
        } catch (RuntimeException e) {
            // Unexpected provider/runtime issue
            throw new VeriLogCryptoException("crypto.sig_decode_failed", e);
        }

        try {
            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
            signer.init(false, pub);
            return signer.verifySignature(digest, rs[0], rs[1]);
        } catch (RuntimeException e) {
            // unexpected failure in signer
            throw new VeriLogCryptoException("crypto.verify_failed", e);
        }
    }
}