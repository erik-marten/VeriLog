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

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** Structural repair of an active file. Authentication-sensitive callers must verify it first. */
public final class FramedTailRepair {
    private static final int FIXED_HEADER_LENGTH = 8;
    private static final int MIN_PAYLOAD_LENGTH = 1 + 8 + 24;
    private static final int MAX_PAYLOAD_LENGTH = 64 * 1024 * 1024;

    private FramedTailRepair() { }

    /** Truncates only an incomplete final frame length or payload; returns bytes removed. */
    public static long truncateIncompleteTail(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            return truncateIncompleteTail(channel);
        }
    }

    static long truncateIncompleteTail(FileChannel channel) throws IOException {
        long size = channel.size();
        channel.position(0);
        ByteBuffer fixed = ByteBuffer.allocate(FIXED_HEADER_LENGTH).order(ByteOrder.BIG_ENDIAN);
        readFully(channel, fixed);
        fixed.flip();
        if (fixed.get() != 'V' || fixed.get() != 'L' || fixed.get() != 'O' || fixed.get() != 'G') {
            throw new IOException("Invalid VLOG magic");
        }
        if (fixed.get() != 1) throw new IOException("Unsupported VLOG version");
        fixed.get(); // flags
        int headerLength = fixed.getShort() & 0xffff;
        long lastComplete = (long) FIXED_HEADER_LENGTH + headerLength;
        if (lastComplete > size) throw new EOFException("Incomplete VLOG header");

        ByteBuffer length = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        while (lastComplete < size) {
            long remaining = size - lastComplete;
            if (remaining < Integer.BYTES) break;
            channel.position(lastComplete);
            length.clear();
            readFully(channel, length);
            length.flip();
            int payloadLength = length.getInt();
            if (payloadLength < MIN_PAYLOAD_LENGTH || payloadLength > MAX_PAYLOAD_LENGTH) {
                throw new IOException("Invalid VLOG frame payload length: " + payloadLength);
            }
            long frameEnd = lastComplete + Integer.BYTES + payloadLength;
            if (frameEnd > size) break;
            lastComplete = frameEnd;
        }
        if (lastComplete != size) {
            channel.truncate(lastComplete);
            channel.force(true);
        }
        return size - lastComplete;
    }

    private static void readFully(FileChannel channel, ByteBuffer bytes) throws IOException {
        while (bytes.hasRemaining()) {
            if (channel.read(bytes) < 0) throw new EOFException();
        }
    }
}
