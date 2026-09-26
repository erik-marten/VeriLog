/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.io;

import io.github.em.verilog.crypto.XChaCha20Poly1305;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/** Encodes one encrypted frame, including its four-byte payload length. */
public final class EncryptedFrameCodec {

    private static final int DEK_LEN = 32;
    private static final int LEN_PREFIX_BYTES = 4;
    private static final int TYPE_BYTES = 1;
    private static final int SEQ_BYTES = 8;
    private static final int NONCE_BYTES = 24;
    private static final byte AAD_SEP = 0x00;
    private static final int AAD_FIXED_BYTES = 1 + 8 + 1 + 1;

    private final byte[] dek32;
    private final byte[] aadPrefix;
    private final SecureRandom rng;

    public EncryptedFrameCodec(byte[] dek32, String aadPrefix) {
        this(dek32, aadPrefix, new SecureRandom());
    }

    EncryptedFrameCodec(byte[] dek32, String aadPrefix, SecureRandom rng) {
        if (dek32 == null || dek32.length != DEK_LEN) throw new IllegalArgumentException("DEK must be 32 bytes");
        this.dek32 = dek32.clone();
        this.aadPrefix = aadPrefix.getBytes(StandardCharsets.UTF_8);
        this.rng = rng;
    }

    public byte[] encode(byte type, long sequence, byte[] plaintext) {
        byte[] nonce = XChaCha20Poly1305.randomNonce(rng);
        byte[] aad = buildAad(type, sequence);
        byte[] ct = XChaCha20Poly1305.encrypt(dek32, nonce, plaintext, aad);

        int payloadLen = TYPE_BYTES + SEQ_BYTES + NONCE_BYTES + ct.length;
        ByteBuffer frame = ByteBuffer.allocate(LEN_PREFIX_BYTES + payloadLen).order(ByteOrder.BIG_ENDIAN);
        frame.putInt(payloadLen);
        frame.put(type);
        frame.putLong(sequence);
        frame.put(nonce);
        frame.put(ct);
        return frame.array();
    }

    private byte[] buildAad(byte type, long sequence) {
        ByteBuffer bb = ByteBuffer.allocate(aadPrefix.length + AAD_FIXED_BYTES).order(ByteOrder.BIG_ENDIAN);
        bb.put(aadPrefix);
        bb.put(AAD_SEP);
        bb.putLong(sequence);
        bb.put(AAD_SEP);
        bb.put(type);
        return bb.array();
    }
}
