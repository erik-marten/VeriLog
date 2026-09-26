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

import io.github.em.verilog.errors.VeriLogIoException;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.Instant;

public final class FramedLogFile implements Closeable {

    public static final byte TYPE_LOG = 0x01;

    private static final byte[] MAGIC = new byte[]{'V', 'L', 'O', 'G'};
    private static final VlogHeaderCodec HEADER_CODEC = new VlogHeaderCodec();
    private static final int FIXED_HEADER_LEN = 4 + 1 + 1 + 2; // magic + version + flags + headerLen
    private static final int TYPE_BYTES = 1;
    private static final int SEQ_BYTES = 8;
    private static final int MAX_PAYLOAD_LEN = 64 * 1024 * 1024;
    private static final long HEADER_LEN_OFFSET = 4L + 1 + 1; // magic + version + flags
    private static final int HEADER_LEN_BYTES = 2;
    private static final int FRAME_HEADER_BYTES = TYPE_BYTES + SEQ_BYTES;

    private final FileChannel ch;
    private final EncryptedFrameCodec codec;
    private final String aadPrefix;

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
        this.codec = new EncryptedFrameCodec(dek32, aad, rng);
        this.ch = ch;
        this.aadPrefix = aad;
    }

    public long nextSeq() {
        return nextSeq;
    }

    public void appendEncryptedJson(byte type, long seq, byte[] plaintextUtf8Json) throws IOException {
        ByteBuffer frame = ByteBuffer.wrap(codec.encode(type, seq, plaintextUtf8Json));
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
        ByteBuffer buf = ByteBuffer.wrap(HEADER_CODEC.encode(aadPrefix, Instant.now()));
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
            if (r < Integer.BYTES) {
                break;
            }

            lenBuf.flip();
            int payloadLen = lenBuf.getInt();

            long frameEnd = ch.position() + payloadLen;
            if (payloadLen <= 0 || payloadLen > MAX_PAYLOAD_LEN || frameEnd > size) {
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
        pos = (long) FIXED_HEADER_LEN + headerLen;

        long maxSeq = 0;
        ch.position(pos);

        ByteBuffer lenBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        ByteBuffer headBuf = ByteBuffer.allocate(1 + 8).order(ByteOrder.BIG_ENDIAN);

        while (true) {
            lenBuf.clear();
            int r = ch.read(lenBuf);
            if (r < Integer.BYTES) {
                break; // EOF or partial length
            }

            lenBuf.flip();
            int payloadLen = lenBuf.getInt();
            if (payloadLen < (TYPE_BYTES + SEQ_BYTES) || payloadLen > MAX_PAYLOAD_LEN) {
                break; // corrupt or insane frame
            }

            headBuf.clear();
            readFully(headBuf);
            headBuf.flip();

            headBuf.get(); // type
            long seq = headBuf.getLong();
            maxSeq = Math.max(maxSeq, seq);

            long skip = (long) payloadLen - FRAME_HEADER_BYTES;
            ch.position(ch.position() + skip);
        }
        return maxSeq + 1;
    }

    private void readFully(ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            int r = ch.read(buf);
            if (r == -1) throw new EOFException();
        }
    }
}
