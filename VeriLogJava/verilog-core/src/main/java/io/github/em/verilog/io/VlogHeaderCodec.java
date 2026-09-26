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

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.Objects;

/** Encodes the complete .vlog file header from supplied values. */
public final class VlogHeaderCodec {

    private static final byte[] MAGIC = new byte[]{'V', 'L', 'O', 'G'};
    private static final int FIXED_HEADER_LEN = 4 + 1 + 1 + 2;
    private static final int MAX_HEADER_JSON_LEN = 0xFFFF;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public byte[] encode(String aadPrefix, Instant createdAt) throws IOException {
        Objects.requireNonNull(aadPrefix, "aadPrefix");
        Objects.requireNonNull(createdAt, "createdAt");

        ObjectNode header = MAPPER.createObjectNode()
                .put("v", 1)
                .put("alg", "XChaCha20-Poly1305")
                .put("aad", aadPrefix)
                .put("createdAt", createdAt.toString());
        LimitedHeaderOutputStream json = new LimitedHeaderOutputStream();
        try (JsonGenerator generator = MAPPER.getFactory().createGenerator(json, JsonEncoding.UTF8)) {
            MAPPER.writeTree(generator, header);
        }
        byte[] headerJson = json.toByteArray();

        ByteBuffer buf = ByteBuffer.allocate(FIXED_HEADER_LEN + headerJson.length).order(ByteOrder.BIG_ENDIAN);
        buf.put(MAGIC);
        buf.put((byte) 1);
        buf.put((byte) 0x01); // encrypted records
        buf.putShort((short) headerJson.length);
        buf.put(headerJson);
        return buf.array();
    }

    private static final class LimitedHeaderOutputStream extends OutputStream {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        @Override
        public void write(int value) throws IOException {
            checkLength(1);
            bytes.write(value);
        }

        @Override
        public void write(byte[] values, int offset, int length) throws IOException {
            checkLength(length);
            bytes.write(values, offset, length);
        }

        private void checkLength(int additionalBytes) throws IOException {
            if (additionalBytes > MAX_HEADER_JSON_LEN - bytes.size()) {
                throw new IOException("Header too large");
            }
        }

        private byte[] toByteArray() {
            return bytes.toByteArray();
        }
    }
}
