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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MarkerFactory;
import org.slf4j.event.KeyValuePair;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LogbackAuditSemanticsResolverTest {

    private static final String EVENT_TYPE_KEY = "verilog.eventType";
    private final LogbackAuditSemanticsResolver resolver = new LogbackAuditSemanticsResolver();

    @Test
    void should_resolve_valid_event_type() {
        LoggingEvent event = eventWithEventType("USER_LOGIN");

        assertEquals(Optional.of("USER_LOGIN"), resolver.resolveEventType(event));
    }

    @Test
    void should_return_empty_when_key_value_pairs_are_null_or_empty() {
        LoggingEvent event = new LoggingEvent();
        assertEquals(Optional.empty(), resolver.resolveEventType(event));

        event.setKeyValuePairs(List.of());
        assertEquals(Optional.empty(), resolver.resolveEventType(event));
    }

    @Test
    void should_return_empty_for_unrelated_key_value_pairs() {
        LoggingEvent event = new LoggingEvent();
        event.setKeyValuePairs(List.of(
                new KeyValuePair("eventType", "USER_LOGIN"),
                new KeyValuePair("verilog.actor", "alice"),
                new KeyValuePair("VERILOG.EVENTTYPE", "USER_LOGIN")
        ));

        assertEquals(Optional.empty(), resolver.resolveEventType(event));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "\t\n"})
    void should_reject_blank_event_type(String eventType) {
        LoggingEvent event = eventWithEventType(eventType);

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> resolver.resolveEventType(event));

        assertEquals("verilog.eventType value must not be blank", error.getMessage());
    }

    @Test
    void should_reject_null_event_type() {
        LoggingEvent event = eventWithEventType(null);

        NullPointerException error = assertThrows(NullPointerException.class,
                () -> resolver.resolveEventType(event));

        assertEquals("verilog.eventType value", error.getMessage());
    }

    @Test
    void should_reject_non_string_event_type() {
        for (Object value : List.of(42, new Object())) {
            LoggingEvent event = eventWithEventType(value);

            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> resolver.resolveEventType(event));

            assertEquals("verilog.eventType value must be a String", error.getMessage());
        }
    }

    @Test
    void should_reject_duplicate_event_type() {
        LoggingEvent event = eventWithEventType("USER_LOGIN");
        event.addKeyValuePair(new KeyValuePair(EVENT_TYPE_KEY, "ACCESS_CHECK"));

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> resolver.resolveEventType(event));

        assertEquals("verilog.eventType must occur at most once", error.getMessage());
    }

    @Test
    void should_be_independent_of_level() {
        for (Level level : new Level[]{Level.TRACE, Level.DEBUG, Level.INFO, Level.WARN, Level.ERROR}) {
            LoggingEvent event = new LoggingEvent();
            event.setLevel(level);

            assertEquals(Optional.empty(), resolver.resolveEventType(event));

            event.addKeyValuePair(new KeyValuePair(EVENT_TYPE_KEY, "USER_LOGIN"));
            assertEquals(Optional.of("USER_LOGIN"), resolver.resolveEventType(event));
        }
    }

    @Test
    void should_be_independent_of_logger_name() {
        LoggingEvent event = new LoggingEvent();
        event.setLoggerName("USER_LOGIN");

        assertEquals(Optional.empty(), resolver.resolveEventType(event));

        event.addKeyValuePair(new KeyValuePair(EVENT_TYPE_KEY, "USER_LOGIN"));
        assertEquals(Optional.of("USER_LOGIN"), resolver.resolveEventType(event));
    }

    @Test
    void should_be_independent_of_mdc() {
        LoggingEvent event = new LoggingEvent();
        event.setMDCPropertyMap(Map.of(EVENT_TYPE_KEY, "USER_LOGIN"));

        assertEquals(Optional.empty(), resolver.resolveEventType(event));

        event.addKeyValuePair(new KeyValuePair(EVENT_TYPE_KEY, "USER_LOGIN"));
        assertEquals(Optional.of("USER_LOGIN"), resolver.resolveEventType(event));
    }

    @Test
    void should_be_independent_of_marker() {
        LoggingEvent event = new LoggingEvent();
        event.addMarker(MarkerFactory.getMarker("USER_LOGIN"));

        assertEquals(Optional.empty(), resolver.resolveEventType(event));

        event.addKeyValuePair(new KeyValuePair(EVENT_TYPE_KEY, "USER_LOGIN"));
        assertEquals(Optional.of("USER_LOGIN"), resolver.resolveEventType(event));
    }

    @Test
    void should_reject_null_event() {
        NullPointerException error = assertThrows(NullPointerException.class,
                () -> resolver.resolveEventType(null));

        assertEquals("event", error.getMessage());
    }

    private static LoggingEvent eventWithEventType(Object eventType) {
        LoggingEvent event = new LoggingEvent();
        event.addKeyValuePair(new KeyValuePair(EVENT_TYPE_KEY, eventType));
        return event;
    }
}
