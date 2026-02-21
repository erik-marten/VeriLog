/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;
import java.util.Arrays;

public final class XChaCha20Poly1305 {
    public static final int KEY_LEN = 32;
    public static final int NONCE_LEN = 24;
    private static final int TAG_LEN_BITS = 128;

    private XChaCha20Poly1305() {}

    public static byte[] randomNonce(SecureRandom rng) {
        byte[] n = new byte[NONCE_LEN];
        rng.nextBytes(n);
        return n;
    }

    public static byte[] encrypt(byte[] key32, byte[] nonce24, byte[] plaintext, byte[] aad) {
        requireLen(key32, KEY_LEN, "key");
        requireLen(nonce24, NONCE_LEN, "nonce");

        byte[] subKey = HChaCha20.subKey(key32, Arrays.copyOfRange(nonce24, 0, 16));
        byte[] nonce12 = new byte[12];
        System.arraycopy(nonce24, 16, nonce12, 4, 8);

        ChaCha20Poly1305 aead = new ChaCha20Poly1305();
        aead.init(true, new AEADParameters(new KeyParameter(subKey), TAG_LEN_BITS, nonce12, aad));

        byte[] out = new byte[aead.getOutputSize(plaintext.length)];
        int off = aead.processBytes(plaintext, 0, plaintext.length, out, 0);
        try {
            off += aead.doFinal(out, off);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException(e);
        }
        return (off == out.length) ? out : Arrays.copyOf(out, off);
    }

    public static byte[] decrypt(byte[] key32, byte[] nonce24, byte[] ciphertextAndTag, byte[] aad)
            throws InvalidCipherTextException {
        requireLen(key32, KEY_LEN, "key");
        requireLen(nonce24, NONCE_LEN, "nonce");

        byte[] subKey = HChaCha20.subKey(key32, Arrays.copyOfRange(nonce24, 0, 16));
        byte[] nonce12 = new byte[12];
        System.arraycopy(nonce24, 16, nonce12, 4, 8);

        ChaCha20Poly1305 aead = new ChaCha20Poly1305();
        aead.init(false, new AEADParameters(new KeyParameter(subKey), TAG_LEN_BITS, nonce12, aad));

        byte[] out = new byte[aead.getOutputSize(ciphertextAndTag.length)];
        int off = aead.processBytes(ciphertextAndTag, 0, ciphertextAndTag.length, out, 0);
        off += aead.doFinal(out, off);
        return (off == out.length) ? out : Arrays.copyOf(out, off);
    }

    private static void requireLen(byte[] b, int len, String name) {
        if (b == null) throw new NullPointerException(name);
        if (b.length != len) throw new IllegalArgumentException(name + " must be " + len + " bytes");
    }
}