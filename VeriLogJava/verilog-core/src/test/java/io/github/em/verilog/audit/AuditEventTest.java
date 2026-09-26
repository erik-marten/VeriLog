/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.audit;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuditEventTest {

    private static final Instant TIMESTAMP = Instant.parse("2026-02-20T12:34:56.789Z");

    @Test
    void should_create_valid_event() {
        AuditEvent event = new AuditEvent(
                TIMESTAMP,
                "api",
                "USER_LOGIN",
                Map.of("action", "login")
        );

        assertEquals(TIMESTAMP, event.timestamp());
        assertEquals("api", event.actor());
        assertEquals("USER_LOGIN", event.eventType());
        assertEquals(Map.of("action", "login"), event.data());
    }

    @Test
    void should_reject_null_timestamp() {
        NullPointerException error = assertThrows(
                NullPointerException.class,
                () -> new AuditEvent(null, "api", "USER_LOGIN", Map.of())
        );

        assertEquals("timestamp", error.getMessage());
    }

    @Test
    void should_reject_null_or_blank_actor() {
        NullPointerException nullError = assertThrows(
                NullPointerException.class,
                () -> new AuditEvent(TIMESTAMP, null, "USER_LOGIN", Map.of())
        );
        IllegalArgumentException blankError = assertThrows(
                IllegalArgumentException.class,
                () -> new AuditEvent(TIMESTAMP, " \t", "USER_LOGIN", Map.of())
        );

        assertEquals("actor", nullError.getMessage());
        assertEquals("actor must not be blank", blankError.getMessage());
    }

    @Test
    void should_reject_null_or_blank_event_type() {
        NullPointerException nullError = assertThrows(
                NullPointerException.class,
                () -> new AuditEvent(TIMESTAMP, "api", null, Map.of())
        );
        IllegalArgumentException blankError = assertThrows(
                IllegalArgumentException.class,
                () -> new AuditEvent(TIMESTAMP, "api", "\n", Map.of())
        );

        assertEquals("eventType", nullError.getMessage());
        assertEquals("eventType must not be blank", blankError.getMessage());
    }

    @Test
    void should_preserve_null_data_as_explicit_json_null() {
        AuditEvent event = new AuditEvent(TIMESTAMP, "api", "USER_LOGIN", null);

        assertNull(event.data());
    }

    @Test
    void should_not_change_when_original_map_is_mutated() {
        Map<String, Object> data = new HashMap<>();
        data.put("action", "login");

        AuditEvent event = new AuditEvent(TIMESTAMP, "api", "USER_LOGIN", data);
        data.put("action", "delete-user");

        assertEquals("login", event.data().get("action"));
        assertThrows(UnsupportedOperationException.class,
                () -> event.data().put("action", "delete-user"));
    }

    @Test
    void should_deep_copy_nested_collections() {
        Map<String, Object> nestedMap = new LinkedHashMap<>();
        nestedMap.put("result", "allowed");
        List<Object> nestedList = new ArrayList<>();
        nestedList.add(nestedMap);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("decisions", nestedList);

        AuditEvent event = new AuditEvent(TIMESTAMP, "api", "ACCESS_CHECK", data);
        nestedMap.put("result", "denied");
        nestedList.add("later");

        List<?> eventList = (List<?>) event.data().get("decisions");
        Map<?, ?> eventMap = (Map<?, ?>) eventList.get(0);
        assertEquals(1, eventList.size());
        assertEquals("allowed", eventMap.get("result"));
        assertThrows(UnsupportedOperationException.class, () -> addValue(eventList));
        assertThrows(UnsupportedOperationException.class, () -> putValue(eventMap));
    }

    @Test
    void should_accept_supported_structured_value_types() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("text", "value");
        data.put("flag", true);
        data.put("byte", (byte) 1);
        data.put("short", (short) 2);
        data.put("integer", 3);
        data.put("long", 4L);
        data.put("nothing", null);
        data.put("list", List.of("nested", Map.of("count", 5L)));

        AuditEvent event = new AuditEvent(TIMESTAMP, "api", "SUPPORTED_VALUES", data);

        assertEquals(data, event.data());
    }

    @Test
    void should_reject_unsupported_structured_value_types() {
        assertThrows(IllegalArgumentException.class,
                () -> eventWith(Map.of("floatingPoint", 1.25d)));
        assertThrows(IllegalArgumentException.class,
                () -> eventWith(Map.of("bigInteger", BigInteger.ONE)));
        assertThrows(IllegalArgumentException.class,
                () -> eventWith(Map.of("set", Set.of("unordered"))));
        assertThrows(IllegalArgumentException.class,
                () -> eventWith(Map.of("object", new Object())));
    }

    @Test
    @SuppressWarnings({"rawtypes", "unchecked"})
    void should_reject_non_string_map_keys() {
        Map rawData = new HashMap();
        rawData.put(1, "value");

        assertThrows(IllegalArgumentException.class,
                () -> new AuditEvent(TIMESTAMP, "api", "INVALID_KEY", rawData));
    }

    @Test
    void should_reject_cyclic_structures() {
        Map<String, Object> data = new HashMap<>();
        data.put("self", data);

        assertThrows(IllegalArgumentException.class,
                () -> eventWith(data));
    }

    private static AuditEvent eventWith(Map<String, Object> data) {
        return new AuditEvent(TIMESTAMP, "api", "EVENT", data);
    }

    @SuppressWarnings("unchecked")
    private static void addValue(List<?> list) {
        ((List<Object>) list).add("new");
    }

    @SuppressWarnings("unchecked")
    private static void putValue(Map<?, ?> map) {
        ((Map<Object, Object>) map).put("new", "value");
    }
}
