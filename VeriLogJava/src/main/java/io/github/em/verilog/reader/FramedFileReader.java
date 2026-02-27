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

import io.github.em.verilog.errors.VeriLogFormatException;
import io.github.em.verilog.errors.VeriLogIoException;
import io.github.em.verilog.errors.VeriLogUncheckedException;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public final class FramedFileReader implements AutoCloseable {

    private final Path path;
    private final FileChannel ch;
    private final byte[] aadPrefix;
    private final int headerLenTotal; // bytes to skip before frames

    public FramedFileReader(Path path)
            throws VeriLogIoException, VeriLogFormatException {
        this.path = path;
        try {
            this.ch = FileChannel.open(path, StandardOpenOption.READ);

            ByteBuffer fixed = ByteBuffer.allocate(4 + 1 + 1 + 2)
                    .order(ByteOrder.BIG_ENDIAN);
            readFully(fixed);
            fixed.flip();

            byte[] magic = new byte[4];
            fixed.get(magic);

            if (magic[0] != 'V' || magic[1] != 'L' ||
                    magic[2] != 'O' || magic[3] != 'G') {
                throw new VeriLogFormatException("format.bad_magic");
            }

            byte ver = fixed.get();
            if (ver != 1) {
                throw new VeriLogFormatException(
                        "format.unsupported_version",
                        ver
                );
            }

            fixed.get(); // flags
            int headerLen = fixed.getShort() & 0xFFFF;

            ByteBuffer hdr = ByteBuffer.allocate(headerLen);
            readFully(hdr);
            hdr.flip();

            byte[] hdrBytes = new byte[headerLen];
            hdr.get(hdrBytes);

            this.aadPrefix = hdrBytes;
            this.headerLenTotal = (4 + 1 + 1 + 2) + headerLen;

        } catch (IOException e) {
            throw new VeriLogIoException("io.read_failed", e, path.toString());
        }
    }

    // Test constructor only visible from inside
    FramedFileReader(FileChannel ch, byte[] rawHeaderJson, int headerLenTotal, Path path) {
        this.path = path;
        this.ch = ch;
        this.aadPrefix = rawHeaderJson;
        this.headerLenTotal = headerLenTotal;
    }

    /**
     * Exposes raw header bytes (UTF-8 JSON).
     */
    public byte[] rawHeaderJsonBytes() {
        return aadPrefix;
    }

    public void positionAtFirstFrame() throws IOException {
        ch.position(headerLenTotal);
    }

    public Frame readNextFrame(boolean tolerateTrailingPartial)
            throws VeriLogIoException, VeriLogFormatException {

        try {
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
            if (payloadLen <= 0 || payloadLen > 64 * 1024 * 1024) {
                throw new VeriLogFormatException("format.invalid_payload_length", payloadLen);
            }

            ByteBuffer payload = readPayloadHandlingPartial(payloadLen, tolerateTrailingPartial);
            if (payload == null) {
                return null; // trailing partial tolerated
            }

            byte type = payload.get();
            long seq = payload.getLong();

            byte[] nonce = new byte[24];
            payload.get(nonce);

            byte[] ct = new byte[payload.remaining()];
            payload.get(ct);

            return new Frame(type, seq, nonce, ct);

        } catch (EOFException e) {
            // only reached for "partial length" case above
            if (tolerateTrailingPartial) return null;
            throw new VeriLogIoException("io.partial_frame_length", e);
        } catch (IOException e) {
            throw new VeriLogIoException("io.read_failed", e);
        }
    }

    public Iterable<Frame> frames(boolean tolerateTrailingPartial) {
        return () -> new java.util.Iterator<>() {
            private Frame next;
            private boolean fetched;

            private void fetch() throws VeriLogIoException, VeriLogFormatException {
                if (!fetched) {
                    next = readNextFrame(tolerateTrailingPartial);
                    fetched = true;
                }
            }

            private void fetchUnchecked() {
                try {
                    fetch();
                } catch (VeriLogIoException | VeriLogFormatException e) {
                    throw new VeriLogUncheckedException(e);
                }
            }

            @Override
            public boolean hasNext() {
                fetchUnchecked();
                return next != null;
            }

            @Override
            public Frame next() {
                fetchUnchecked();
                if (next == null) throw new java.util.NoSuchElementException();

                Frame result = next;
                next = null;
                fetched = false;
                return result;
            }
        };
    }

    private ByteBuffer readPayloadHandlingPartial(int payloadLen, boolean tolerateTrailingPartial)
            throws IOException, VeriLogIoException {

        ByteBuffer payload = ByteBuffer
                .allocate(payloadLen)
                .order(ByteOrder.BIG_ENDIAN);

        try {
            readFully(payload);
            payload.flip();
            return payload;

        } catch (EOFException e) {
            if (tolerateTrailingPartial) {
                return null;
            }
            throw new VeriLogIoException("io.partial_frame_payload", e);
        }
    }

    private void readFully(ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            int r = ch.read(buf);
            if (r == -1) throw new EOFException();
        }
    }

    @Override
    public void close() throws VeriLogIoException {
        try {
            ch.close();
        } catch (IOException e) {
            throw new VeriLogIoException("io.close_failed", e, path.toString());
        }
    }
}