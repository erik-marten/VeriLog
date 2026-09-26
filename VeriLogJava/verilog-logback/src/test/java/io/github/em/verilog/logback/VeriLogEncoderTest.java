/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.logback;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.core.OutputStreamAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.em.verilog.audit.HashChainState;
import io.github.em.verilog.crypto.XChaCha20Poly1305;
import io.github.em.verilog.errors.VeriLogCryptoException;
import io.github.em.verilog.io.FramedLogFile;
import io.github.em.verilog.sign.LogSigner;
import org.junit.jupiter.api.Test;
import org.slf4j.event.KeyValuePair;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class VeriLogEncoderTest {
    private static final String AAD = "VeriLog|v1";
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void requires_complete_valid_configuration_and_reports_errors() throws Exception {
        VeriLogEncoder empty = new VeriLogEncoder();
        empty.setContext(new LoggerContext());
        empty.start();
        assertFalse(empty.isStarted());
        assertTrue(empty.getContext().getStatusManager().getCopyOfStatusList().stream()
                .anyMatch(status -> status.getMessage().contains("chain state")));
        assertThrows(IllegalStateException.class, () -> empty.encode(event("evt")));

        VeriLogEncoder encoder = configured(HashChainState.fresh(), VeriLogEncoder.InitialStreamMode.NEW, signer(), key());
        encoder.setActor(" ");
        encoder.setDek32(new byte[31]);
        encoder.setAadPrefix(null);
        encoder.setInitialChainState(new HashChainState(0, "bad"));
        encoder.setInitialStreamMode(null);
        encoder.start();
        assertFalse(encoder.isStarted());

        encoder.setActor("static-actor");
        encoder.setDek32(key());
        encoder.setAadPrefix(AAD);
        encoder.setInitialChainState(HashChainState.fresh());
        encoder.setInitialStreamMode(VeriLogEncoder.InitialStreamMode.NEW);
        encoder.start();
        assertTrue(encoder.isStarted());
        assertTrue(encoder.isStateful());
        assertThrows(IllegalStateException.class, () -> encoder.setActor("other"));
        assertThrows(IllegalStateException.class, () -> encoder.setDek32(key()));
        assertThrows(IllegalStateException.class, () -> encoder.setSigner(signer()));
        assertThrows(IllegalStateException.class, () -> encoder.setAadPrefix("other"));
        assertThrows(IllegalStateException.class, () -> encoder.setInitialChainState(HashChainState.fresh()));
        assertThrows(IllegalStateException.class, () -> encoder.setInitialStreamMode(VeriLogEncoder.InitialStreamMode.RESUME));
        encoder.stop();
        assertThrows(IllegalStateException.class, () -> encoder.setInitialChainState(HashChainState.fresh()));
        encoder.start();
        assertFalse(encoder.isStarted(), "restart must not reuse the original sequence");
    }

    @Test
    void ignores_unmarked_events_and_preserves_invalid_metadata_errors() throws Exception {
        VeriLogEncoder encoder = started(HashChainState.fresh(), VeriLogEncoder.InitialStreamMode.NEW, signer(), key());
        LoggingEvent ordinary = event(null);
        ordinary.setKeyValuePairs(List.of(new KeyValuePair("other", "evt")));
        assertEquals(0, encoder.encode(ordinary).length);

        LoggingEvent invalid = event(" ");
        assertEquals("verilog.eventType value must not be blank",
                assertThrows(IllegalArgumentException.class, () -> encoder.encode(invalid)).getMessage());
        LoggingEvent duplicate = event("evt");
        duplicate.addKeyValuePair(new KeyValuePair("verilog.eventType", "another"));
        assertEquals("verilog.eventType must occur at most once",
                assertThrows(IllegalArgumentException.class, () -> encoder.encode(duplicate)).getMessage());
        LoggingEvent nullValue = event(null);
        nullValue.addKeyValuePair(new KeyValuePair("verilog.eventType", null));
        assertEquals("verilog.eventType value",
                assertThrows(NullPointerException.class, () -> encoder.encode(nullValue)).getMessage());

        JsonNode first = decrypt(encoder.encode(event("LOGIN")), key());
        assertEquals(1, first.get("seq").asLong());
        assertEquals("LOGIN", first.get("eventType").asText());
    }

    @Test
    void maps_event_signs_and_frames_with_contiguous_chain() throws Exception {
        VeriLogEncoder encoder = started(HashChainState.fresh(), VeriLogEncoder.InitialStreamMode.NEW, signer(), key());
        byte[] firstFrame = encoder.encode(event("LOGIN"));
        byte[] secondFrame = encoder.encode(event("LOGOUT"));
        JsonNode first = decrypt(firstFrame, key());
        JsonNode second = decrypt(secondFrame, key());

        assertEquals(1, first.get("seq").asLong());
        assertEquals(2, second.get("seq").asLong());
        assertEquals("0".repeat(64), first.get("prevHash").asText());
        assertEquals(first.get("entryHash").asText(), second.get("prevHash").asText());
        assertEquals("static-actor", first.get("actor").asText());
        assertEquals("LOGIN", first.get("eventType").asText());
        assertEquals("message 1", first.get("event").get("message").asText());
        assertEquals("test.logger", first.get("event").get("logger").asText());
        assertEquals("INFO", first.get("event").get("level").asText());
        assertEquals("worker", first.get("event").get("thread").asText());
        assertEquals("abc", first.get("event").get("mdc").get("requestId").asText());
    }

    @Test
    void starts_from_supplied_recovered_chain_and_snapshots_it() throws Exception {
        String previous = "a".repeat(64);
        HashChainState recovered = new HashChainState(42, previous);
        VeriLogEncoder encoder = started(recovered, VeriLogEncoder.InitialStreamMode.RESUME, signer(), key());
        recovered.allocateSeq();
        recovered.updatePrevHash("b".repeat(64));
        JsonNode signed = decrypt(encoder.encode(event("evt")), key());
        assertEquals(42, signed.get("seq").asLong());
        assertEquals(previous, signed.get("prevHash").asText());
    }

    @Test
    void failed_signing_does_not_advance_chain() throws Exception {
        LogSigner flaky = mock(LogSigner.class);
        when(flaky.keyId()).thenReturn("test-key");
        when(flaky.signEntryHash(any())).thenThrow(new VeriLogCryptoException("crypto.sign_failed"))
                .thenReturn(new byte[64]);
        VeriLogEncoder encoder = started(new HashChainState(9, "a".repeat(64)),
                VeriLogEncoder.InitialStreamMode.NEW, flaky, key());

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> encoder.encode(event("evt")));
        assertInstanceOf(VeriLogCryptoException.class, failure.getCause());
        JsonNode retry = decrypt(encoder.encode(event("evt")), key());
        assertEquals(9, retry.get("seq").asLong());
        assertEquals("a".repeat(64), retry.get("prevHash").asText());
        assertEquals(10, decrypt(encoder.encode(event("evt")), key()).get("seq").asLong());
    }

    @Test
    void new_and_resume_header_lifecycle_and_footer() throws Exception {
        for (VeriLogEncoder.InitialStreamMode mode : VeriLogEncoder.InitialStreamMode.values()) {
            VeriLogEncoder encoder = started(HashChainState.fresh(), mode, signer(), key());
            Instant beforeFirst = Instant.now();
            byte[] first = encoder.headerBytes();
            Instant afterFirst = Instant.now();
            if (mode == VeriLogEncoder.InitialStreamMode.RESUME) {
                assertEquals(0, first.length);
            } else {
                assertHeader(first, beforeFirst, afterFirst);
            }
            for (int i = 0; i < 2; i++) {
                Instant before = Instant.now();
                byte[] next = encoder.headerBytes();
                Instant after = Instant.now();
                assertHeader(next, before, after);
            }
            assertEquals(0, encoder.footerBytes().length);
        }
    }

    @Test
    void clones_dek_before_start() throws Exception {
        byte[] supplied = key();
        VeriLogEncoder encoder = configured(HashChainState.fresh(), VeriLogEncoder.InitialStreamMode.NEW, signer(), supplied);
        Arrays.fill(supplied, (byte) 0xff);
        encoder.start();
        decrypt(encoder.encode(event("evt")), key());
    }

    @Test
    void output_stream_appender_serializes_concurrent_stateful_encoding_and_writes() throws Exception {
        VeriLogEncoder encoder = started(HashChainState.fresh(), VeriLogEncoder.InitialStreamMode.NEW, signer(), key());
        assertTrue(encoder.isStateful());
        LoggerContext context = new LoggerContext();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        OutputStreamAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender = new OutputStreamAppender<>();
        appender.setContext(context);
        appender.setName("audit");
        appender.setEncoder(encoder);
        appender.setOutputStream(output);
        appender.start();
        assertTrue(appender.isStarted());

        int threads = 8;
        int perThread = 30;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int thread = 0; thread < threads; thread++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < perThread; i++) appender.doAppend(event("evt"));
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) future.get();
        } finally {
            pool.shutdownNow();
            appender.stop();
        }

        ByteBuffer bytes = ByteBuffer.wrap(output.toByteArray()).order(ByteOrder.BIG_ENDIAN);
        int headerLength = 8 + (bytes.getShort(6) & 0xffff);
        bytes.position(headerLength);
        String previous = "0".repeat(64);
        HashSet<Long> sequences = new HashSet<>();
        for (long expected = 1; expected <= threads * perThread; expected++) {
            assertTrue(bytes.hasRemaining(), "missing frame " + expected);
            int frameLength = bytes.getInt(bytes.position());
            byte[] frame = new byte[4 + frameLength];
            bytes.get(frame);
            JsonNode signed = decrypt(frame, key());
            assertEquals(expected, signed.get("seq").asLong());
            assertEquals(previous, signed.get("prevHash").asText());
            assertTrue(sequences.add(expected), "duplicate sequence " + expected);
            previous = signed.get("entryHash").asText();
        }
        assertFalse(bytes.hasRemaining());
        assertEquals(threads * perThread, sequences.size());
    }

    private static void assertHeader(byte[] bytes, Instant before, Instant after) throws Exception {
        assertArrayEquals(new byte[]{'V', 'L', 'O', 'G'}, Arrays.copyOfRange(bytes, 0, 4));
        assertEquals(1, bytes[4]);
        assertEquals(1, bytes[5]);
        int length = ByteBuffer.wrap(bytes, 6, 2).getShort() & 0xffff;
        assertEquals(bytes.length - 8, length);
        JsonNode json = JSON.readTree(Arrays.copyOfRange(bytes, 8, bytes.length));
        assertEquals(1, json.get("v").asInt());
        assertEquals("XChaCha20-Poly1305", json.get("alg").asText());
        assertEquals(AAD, json.get("aad").asText());
        Instant createdAt = Instant.parse(json.get("createdAt").asText());
        assertFalse(createdAt.isBefore(before));
        assertFalse(createdAt.isAfter(after));
    }

    private static JsonNode decrypt(byte[] frame, byte[] dek) throws Exception {
        ByteBuffer bytes = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN);
        assertEquals(frame.length - 4, bytes.getInt());
        assertEquals(FramedLogFile.TYPE_LOG, bytes.get());
        long sequence = bytes.getLong();
        byte[] nonce = new byte[24];
        bytes.get(nonce);
        byte[] ciphertext = new byte[bytes.remaining()];
        bytes.get(ciphertext);
        byte[] prefix = AAD.getBytes(StandardCharsets.UTF_8);
        ByteBuffer aad = ByteBuffer.allocate(prefix.length + 11).order(ByteOrder.BIG_ENDIAN);
        aad.put(prefix).put((byte) 0).putLong(sequence).put((byte) 0).put(FramedLogFile.TYPE_LOG);
        JsonNode signed = JSON.readTree(XChaCha20Poly1305.decrypt(dek, nonce, ciphertext, aad.array()));
        assertEquals(sequence, signed.get("seq").asLong());
        return signed;
    }

    private static VeriLogEncoder started(HashChainState state, VeriLogEncoder.InitialStreamMode mode,
                                         LogSigner signer, byte[] dek) {
        VeriLogEncoder encoder = configured(state, mode, signer, dek);
        encoder.start();
        assertTrue(encoder.isStarted());
        return encoder;
    }

    private static VeriLogEncoder configured(HashChainState state, VeriLogEncoder.InitialStreamMode mode,
                                            LogSigner signer, byte[] dek) {
        VeriLogEncoder encoder = new VeriLogEncoder();
        encoder.setContext(new LoggerContext());
        encoder.setActor("static-actor");
        encoder.setSigner(signer);
        encoder.setDek32(dek);
        encoder.setAadPrefix(AAD);
        encoder.setInitialChainState(state);
        encoder.setInitialStreamMode(mode);
        return encoder;
    }

    private static LogSigner signer() throws VeriLogCryptoException {
        LogSigner signer = mock(LogSigner.class);
        when(signer.keyId()).thenReturn("test-key");
        when(signer.signEntryHash(any())).thenReturn(new byte[64]);
        return signer;
    }

    private static byte[] key() {
        byte[] result = new byte[32];
        for (int i = 0; i < result.length; i++) result[i] = (byte) i;
        return result;
    }

    private static LoggingEvent event(String eventType) {
        LoggingEvent event = new LoggingEvent();
        event.setInstant(Instant.parse("2026-09-26T12:00:00Z"));
        event.setMessage("message {}");
        event.setArgumentArray(new Object[]{1});
        event.setLoggerName("test.logger");
        event.setLevel(Level.INFO);
        event.setThreadName("worker");
        event.setMDCPropertyMap(Map.of("requestId", "abc"));
        if (eventType != null) event.addKeyValuePair(new KeyValuePair("verilog.eventType", eventType));
        return event;
    }
}
