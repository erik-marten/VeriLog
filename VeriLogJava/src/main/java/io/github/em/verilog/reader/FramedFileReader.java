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

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public final class FramedFileReader implements AutoCloseable {

    private final FileChannel ch;
    private final byte[] aadPrefix;
    private final byte[] fileIdBytes; // optional for later for now null
    private final int headerLenTotal; // bytes to skip before frames

    public static final class Header {
        public final String aad;
        public Header(String aad) { this.aad = aad; }
    }

    public FramedFileReader(Path path) throws IOException {
        this.ch = FileChannel.open(path, StandardOpenOption.READ);

        // Read fixed header: magic(4) version(1) flags(1) headerLen(2)
        ByteBuffer fixed = ByteBuffer.allocate(4 + 1 + 1 + 2).order(ByteOrder.BIG_ENDIAN);
        readFully(fixed); fixed.flip();

        byte[] magic = new byte[4];
        fixed.get(magic);
        if (magic[0] != 'V' || magic[1] != 'L' || magic[2] != 'O' || magic[3] != 'G')
            throw new IOException("Bad magic");

        byte ver = fixed.get();
        if (ver != 1) throw new IOException("Unsupported version: " + ver);

        fixed.get(); // flags
        int headerLen = fixed.getShort() & 0xFFFF;

        ByteBuffer hdr = ByteBuffer.allocate(headerLen);
        readFully(hdr); hdr.flip();

        // For now: only need "aad" string. JSON parsed in VeriLogReader.
        byte[] hdrBytes = new byte[headerLen];
        hdr.get(hdrBytes);

        // keep raw header bytes for parsing in VeriLogReader
        this.aadPrefix = hdrBytes; // TEMP store: replaced with parsed aad bytes in VeriLogReader
        this.fileIdBytes = null;
        this.headerLenTotal = (4 + 1 + 1 + 2) + headerLen;
    }

    /** Exposes raw header bytes (UTF-8 JSON). */
    public byte[] rawHeaderJsonBytes() {
        return aadPrefix;
    }

    public void positionAtFirstFrame() throws IOException {
        ch.position(headerLenTotal);
    }

    public Frame readNextFrame(boolean tolerateTrailingPartial) throws IOException {
        // len (4)
        ByteBuffer lenBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        int r = ch.read(lenBuf);

        if (r == -1) return null;
        if (r < 4) {
            if (tolerateTrailingPartial) return null;
            throw new EOFException("Partial frame length");
        }

        lenBuf.flip();
        int payloadLen = lenBuf.getInt();
        if (payloadLen <= 0 || payloadLen > 64 * 1024 * 1024)
            throw new IOException("Invalid payloadLen: " + payloadLen);

        ByteBuffer payload = ByteBuffer.allocate(payloadLen).order(ByteOrder.BIG_ENDIAN);
        try {
            readFully(payload);
        } catch (EOFException e) {
            if (tolerateTrailingPartial) return null;
            throw e;
        }
        payload.flip();

        byte type = payload.get();
        long seq = payload.getLong();

        byte[] nonce = new byte[24];
        payload.get(nonce);

        byte[] ct = new byte[payload.remaining()];
        payload.get(ct);

        return new Frame(type, seq, nonce, ct);
    }



    private void readFully(ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            int r = ch.read(buf);
            if (r == -1) throw new EOFException();
        }
    }

    @Override public void close() throws IOException { ch.close(); }
}