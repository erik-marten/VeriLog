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
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import io.github.em.verilog.audit.AuditEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MarkerFactory;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class LogbackAuditEventMapperTest {

    private static final Instant TIMESTAMP = Instant.parse("2026-02-20T12:34:56.789123456Z");
    private static final Set<String> DATA_KEYS = Set.of("message", "logger", "level", "thread", "mdc");
    private final LogbackAuditEventMapper mapper = new LogbackAuditEventMapper();

    @Test
    void should_map_timestamp_explicit_semantics_and_normalized_metadata() {
        LoggingEvent source = event(Level.INFO, Map.of("requestId", "abc-123"));
        source.addMarker(MarkerFactory.getMarker("uninterpreted-marker"));
        source.setThrowableProxy(new ThrowableProxy(new IllegalStateException("ignored")));

        AuditEvent result = mapper.map(source, "alice", "USER_LOGIN");

        assertEquals(TIMESTAMP, result.timestamp());
        assertEquals("alice", result.actor());
        assertEquals("USER_LOGIN", result.eventType());
        assertEquals(DATA_KEYS, result.data().keySet());
        assertEquals(Map.of(
                "message", "User alice logged in",
                "logger", "com.example.AuthService",
                "level", "INFO",
                "thread", "http-worker-4",
                "mdc", Map.of("requestId", "abc-123")
        ), result.data());
        assertInstanceOf(String.class, result.data().get("level"));
    }

    @Test
    void should_map_millisecond_timestamp_through_interface_default() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getTimeStamp()).thenReturn(123456789L);
        when(source.getInstant()).thenCallRealMethod();

        assertEquals(Instant.ofEpochMilli(123456789L),
                mapper.map(source, "alice", "USER_LOGIN").timestamp());
    }

    @Test
    void should_preserve_empty_mdc() {
        AuditEvent result = mapper.map(event(Level.INFO, Map.of()), "alice", "USER_LOGIN");

        assertEquals(DATA_KEYS, result.data().keySet());
        assertEquals(Map.of(), result.data().get("mdc"));
    }

    @Test
    void should_snapshot_mdc_event_and_formatted_arguments() {
        Map<String, String> mdc = new LinkedHashMap<>();
        mdc.put("requestId", "abc-123");
        LoggingEvent source = event(Level.INFO, mdc);
        StringBuilder argument = new StringBuilder("alice");
        source.getArgumentArray()[0] = argument;

        AuditEvent result = mapper.map(source, "alice", "USER_LOGIN");
        mdc.put("requestId", "changed");
        mdc.put("later", "value");
        argument.replace(0, argument.length(), "bob");
        source.getArgumentArray()[0] = new Object();
        source.setLoggerName("changed.logger");
        source.setInstant(Instant.EPOCH);

        assertEquals(TIMESTAMP, result.timestamp());
        assertEquals("com.example.AuthService", result.data().get("logger"));
        assertEquals("User alice logged in", result.data().get("message"));
        assertEquals(Map.of("requestId", "abc-123"), result.data().get("mdc"));
        assertThrows(UnsupportedOperationException.class, () -> result.data().clear());
        assertThrows(UnsupportedOperationException.class,
                () -> ((Map<?, ?>) result.data().get("mdc")).clear());
    }

    @Test
    void should_keep_event_type_independent_of_level() {
        for (Level level : new Level[]{Level.TRACE, Level.DEBUG, Level.INFO, Level.WARN, Level.ERROR}) {
            AuditEvent result = mapper.map(event(level, Map.of()), "alice", "USER_LOGIN");

            assertEquals("USER_LOGIN", result.eventType());
            assertEquals(level.toString(), result.data().get("level"));
        }
        assertEquals("ACCESS_CHECK",
                mapper.map(event(Level.INFO, Map.of()), "alice", "ACCESS_CHECK").eventType());
    }

    @Test
    void should_preserve_null_metadata() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getInstant()).thenReturn(TIMESTAMP);
        // MDC is non-null by the Logback contract, unlike the nullable scalar fields.
        when(source.getMDCPropertyMap()).thenReturn(Map.of());

        AuditEvent result = mapper.map(source, "alice", "USER_LOGIN");

        assertEquals(DATA_KEYS, result.data().keySet());
        for (String key : Set.of("message", "logger", "level", "thread")) {
            assertNull(result.data().get(key), key);
        }
        assertEquals(Map.of(), result.data().get("mdc"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t\n"})
    void should_propagate_actor_validation(String actor) {
        Class<? extends RuntimeException> type = actor == null
                ? NullPointerException.class : IllegalArgumentException.class;

        RuntimeException error = assertThrows(type,
                () -> mapper.map(event(Level.INFO, Map.of()), actor, "USER_LOGIN"));

        assertEquals(actor == null ? "actor" : "actor must not be blank", error.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t\n"})
    void should_propagate_event_type_validation(String eventType) {
        Class<? extends RuntimeException> type = eventType == null
                ? NullPointerException.class : IllegalArgumentException.class;

        RuntimeException error = assertThrows(type,
                () -> mapper.map(event(Level.INFO, Map.of()), "alice", eventType));

        assertEquals(eventType == null ? "eventType" : "eventType must not be blank", error.getMessage());
    }

    @Test
    void should_reject_null_event() {
        NullPointerException error = assertThrows(NullPointerException.class,
                () -> mapper.map(null, "alice", "USER_LOGIN"));

        assertEquals("event", error.getMessage());
    }

    private static LoggingEvent event(Level level, Map<String, String> mdc) {
        LoggingEvent event = new LoggingEvent();
        event.setInstant(TIMESTAMP);
        event.setMessage("User {} logged in");
        event.setArgumentArray(new Object[]{"alice"});
        event.setLoggerName("com.example.AuthService");
        event.setLevel(level);
        event.setThreadName("http-worker-4");
        event.setMDCPropertyMap(mdc);
        return event;
    }
}
