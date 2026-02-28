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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.em.verilog.crypto.XChaCha20Poly1305;
import io.github.em.verilog.errors.VeriLogIoException;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;

public final class FramedLogFile implements Closeable {

    public static final byte TYPE_LOG = 0x01;

    private static final byte[] MAGIC = new byte[]{'V', 'L', 'O', 'G'};
    private static final int FIXED_HEADER_LEN = 4 + 1 + 1 + 2; // magic + version + flags + headerLen
    private static final int DEK_LEN = 32;
    private static final int LEN_PREFIX_BYTES = 4;
    private static final int TYPE_BYTES = 1;
    private static final int SEQ_BYTES = 8;
    private static final int NONCE_BYTES = 24;
    private static final int MAX_PAYLOAD_LEN = 64 * 1024 * 1024;
    private static final byte AAD_SEP = 0x00;
    private static final int AAD_FIXED_BYTES = 1 + 8 + 1 + 1;
    private static final long HEADER_LEN_OFFSET = 4L + 1 + 1; // magic + version + flags
    private static final int HEADER_LEN_BYTES = 2;
    private static final int FRAME_HEADER_BYTES = TYPE_BYTES + SEQ_BYTES;

    private final FileChannel ch;
    private final SecureRandom rng;
    private final byte[] dek32;
    private final byte[] aadPrefix; // UTF8(header.aad)

    private long nextSeq; // maintained by logger

    public static FramedLogFile openOrCreate(Path path, byte[] dek32, String aad) throws VeriLogIoException {
        FileChannel ch = null;
        FramedLogFile f = null;

        try {
            Files.createDirectories(path.getParent() == null ? Path.of(".") : path.getParent());
            boolean exists = Files.exists(path);

            ch = FileChannel.open(path,
                    StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);

            f = new FramedLogFile(ch, new SecureRandom(), dek32, aad);

            if (!exists || ch.size() == 0) {
                f.writeHeader();
                f.nextSeq = 1;
            } else {
                f.validateHeaderAndRecover();
                f.nextSeq = f.scanNextSeq();
            }

            ch.position(ch.size());
            return f;

        } catch (IOException e) {
            try {
                if (f != null) {
                    f.close();
                }
            } catch (IOException closeEx) {
                e.addSuppressed(closeEx);
            }
            throw new VeriLogIoException("io.write_failed", e);
        }
    }

    static void closeOnInitFailure(FramedLogFile f, IOException e) {
        try {
            if (f != null) {
                f.close(); // closes channel internally
            }
        } catch (IOException closeEx) {
            e.addSuppressed(closeEx);
        }
    }

    private FramedLogFile(FileChannel ch, SecureRandom rng, byte[] dek32, String aad) {
        if (dek32 == null || dek32.length != DEK_LEN) throw new IllegalArgumentException("DEK must be 32 bytes");
        this.ch = ch;
        this.rng = rng;
        this.dek32 = dek32.clone();
        this.aadPrefix = aad.getBytes(StandardCharsets.UTF_8);
    }

    public long nextSeq() {
        return nextSeq;
    }

    public void appendEncryptedJson(byte type, long seq, byte[] plaintextUtf8Json) throws IOException {
        byte[] nonce = XChaCha20Poly1305.randomNonce(rng);
        byte[] aad = buildAad(type, seq);
        byte[] ct = XChaCha20Poly1305.encrypt(dek32, nonce, plaintextUtf8Json, aad);

        int payloadLen = TYPE_BYTES + SEQ_BYTES + NONCE_BYTES + ct.length; // type + seq + nonce + ct
        ByteBuffer frame = ByteBuffer.allocate(LEN_PREFIX_BYTES + payloadLen).order(ByteOrder.BIG_ENDIAN);
        frame.putInt(payloadLen);
        frame.put(type);
        frame.putLong(seq);
        frame.put(nonce);
        frame.put(ct);
        frame.flip();

        while (frame.hasRemaining()) ch.write(frame);
        nextSeq = seq + 1;
    }

    public void flush(boolean fsync) throws IOException {
        ch.force(fsync);
    }

    @Override
    public void close() throws IOException {
        ch.close();
    }

    // ---------------- header + recovery ----------------

    private void writeHeader() throws IOException {
        ObjectMapper om = new ObjectMapper();
        byte flags = 0x01; // encrypted records

        byte[] headerJson = om.writeValueAsBytes(Map.of(
                "v", 1,
                "alg", "XChaCha20-Poly1305",
                "aad", new String(aadPrefix, StandardCharsets.UTF_8),
                "createdAt", Instant.now().toString()
        ));

        if (headerJson.length > 65535) throw new IOException("Header too large");

        ByteBuffer buf = ByteBuffer.allocate(FIXED_HEADER_LEN + headerJson.length).order(ByteOrder.BIG_ENDIAN);
        buf.put(MAGIC);
        buf.put((byte) 1);           // version
        buf.put(flags);
        buf.putShort((short) headerJson.length);
        buf.put(headerJson);
        buf.flip();

        ch.position(0);
        while (buf.hasRemaining()) ch.write(buf);
        ch.force(true);
    }

    private void validateHeaderAndRecover() throws IOException {
        ch.position(0);
        ByteBuffer fixed = ByteBuffer.allocate(FIXED_HEADER_LEN).order(ByteOrder.BIG_ENDIAN);
        readFully(fixed);
        fixed.flip();

        byte[] magic = new byte[4];
        fixed.get(magic);
        if (!(magic[0] == 'V' && magic[1] == 'L' && magic[2] == 'O' && magic[3] == 'G'))
            throw new IOException("Bad magic");

        byte ver = fixed.get();
        if (ver != 1) throw new IOException("Unsupported version: " + ver);

        /* flags */
        fixed.get();
        int headerLen = fixed.getShort() & 0xFFFF;

        ByteBuffer hdr = ByteBuffer.allocate(headerLen);
        readFully(hdr);

        // Recovery: truncate any partial frame at end
        truncateToLastFullFrame();
    }

    private void truncateToLastFullFrame() throws IOException {
        long size = ch.size();
        long pos;

        // read headerLen to jump correctly
        ch.position(HEADER_LEN_OFFSET);
        ByteBuffer hb = ByteBuffer.allocate(HEADER_LEN_BYTES).order(ByteOrder.BIG_ENDIAN);
        readFully(hb);
        hb.flip();
        int headerLen = hb.getShort() & 0xFFFF;
        pos = (long) FIXED_HEADER_LEN + headerLen;

        long lastGood = pos;
        ch.position(pos);

        ByteBuffer lenBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        while (true) {
            lenBuf.clear();
            int r = ch.read(lenBuf);

            if (r < 4) break;

            lenBuf.flip();
            int payloadLen = lenBuf.getInt();

            long frameEnd = ch.position() + payloadLen;

            if (payloadLen <= 0
                    || payloadLen > MAX_PAYLOAD_LEN
                    || frameEnd > size) {
                break;
            }

            ch.position(frameEnd);
            lastGood = frameEnd;
        }

        if (lastGood != size) {
            ch.truncate(lastGood);
            ch.force(true);
        }
    }

    private long scanNextSeq() throws IOException {
        // Simple scan: read frames, track max seq, return max+1
        long pos;

        ch.position(HEADER_LEN_OFFSET);
        ByteBuffer hb = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN);
        readFully(hb);
        hb.flip();
        int headerLen = hb.getShort() & 0xFFFF;
        pos = FIXED_HEADER_LEN + headerLen;

        long maxSeq = 0;
        ch.position(pos);

        ByteBuffer lenBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        ByteBuffer headBuf = ByteBuffer.allocate(1 + 8).order(ByteOrder.BIG_ENDIAN);

        while (true) {
            lenBuf.clear();
            int r = ch.read(lenBuf);

            if (r == -1 || r < 4) {
                break; // EOF or partial length
            }

            lenBuf.flip();
            int payloadLen = lenBuf.getInt();

            // Need at least type(1) + seq(8) present in payload
            if (payloadLen < (1 + 8) || payloadLen > MAX_PAYLOAD_LEN) {
                break; // corrupt/insane frame
            }

            headBuf.clear();
            readFully(headBuf);
            headBuf.flip();

            headBuf.get(); // type
            long seq = headBuf.getLong();
            if (seq > maxSeq) maxSeq = seq;

            long skip = (long) payloadLen - FRAME_HEADER_BYTES;
            ch.position(ch.position() + skip);
        }
        return maxSeq + 1;
    }

    private byte[] buildAad(byte type, long seq) {
        // aad = prefix || 0x00 || uint64_be(seq) || 0x00 || type
        ByteBuffer bb = ByteBuffer.allocate(aadPrefix.length + AAD_FIXED_BYTES).order(ByteOrder.BIG_ENDIAN);
        bb.put(aadPrefix);
        bb.put(AAD_SEP);
        bb.putLong(seq);
        bb.put(AAD_SEP);
        bb.put(type);
        return bb.array();
    }

    private void readFully(ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            int r = ch.read(buf);
            if (r == -1) throw new EOFException();
        }
    }
}