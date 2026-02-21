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

import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.EcdsaSigCodec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import java.math.BigInteger;

public final class BcEcdsaP256Signer implements LogSigner {

    private final ECPrivateKeyParameters priv;
    private final ECDomainParameters domain;
    private final String keyIdHex;
    private final boolean enforceLowS;

    public BcEcdsaP256Signer(byte[] pkcs8PrivateKeyDer, byte[] spkiPublicKeyDer, boolean enforceLowS) {
        try {
            AsymmetricKeyParameter privKey = PrivateKeyFactory.createKey(pkcs8PrivateKeyDer);
            if (!(privKey instanceof ECPrivateKeyParameters)) {
                throw new IllegalArgumentException("Not an EC private key");
            }
            this.priv = (ECPrivateKeyParameters) privKey;

            var p = priv.getParameters();
            this.domain = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH(), p.getSeed());

            this.enforceLowS = enforceLowS;
            this.keyIdHex = CryptoUtil.toHexLower(CryptoUtil.sha256(spkiPublicKeyDer));
        } catch (Exception e) {
            throw new RuntimeException("Failed to create signer", e);
        }
    }

    @Override
    public String keyId() {
        return keyIdHex;
    }

    @Override
    public byte[] signEntryHash(byte[] entryHash32) {
        if (entryHash32 == null || entryHash32.length != 32)
            throw new IllegalArgumentException("entryHash must be 32 bytes");

        // Sign SHA256(entryHashBytes) with deterministic k (RFC6979)
        byte[] digest = CryptoUtil.sha256(entryHash32);

        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, priv);

        BigInteger[] rs = signer.generateSignature(digest);
        BigInteger r = rs[0];
        BigInteger s = rs[1];

        if (enforceLowS) {
            BigInteger n = domain.getN();
            BigInteger halfN = n.shiftRight(1);
            if (s.compareTo(halfN) > 0) s = n.subtract(s);
        }

        try {
            DSAEncoding enc = StandardDSAEncoding.INSTANCE;
            byte[] der = enc.encode(domain.getN(), r, s);
            return EcdsaSigCodec.derToRaw(der); // -> 64 raw bytes r||s
        } catch (Exception e) {
            throw new RuntimeException("Signature encoding failed", e);
        }
    }
}