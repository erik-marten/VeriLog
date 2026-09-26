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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An immutable, framework-independent event ready for VeriLog's cryptographic pipeline.
 *
 * <p>Event data is limited to JSON-compatible values supported by VeriLog's canonical
 * serializer: string-keyed maps, lists, {@link String}, {@link Boolean}, {@link Byte},
 * {@link Short}, {@link Integer}, {@link Long}, and {@code null}. Other {@link Number}
 * implementations, including floating-point types and {@code BigInteger}, are not supported.
 * Maps and lists are copied recursively.</p>
 */
public final class AuditEvent {

    private final Instant timestamp;
    private final String actor;
    private final String eventType;
    private final Map<String, Object> data;

    /**
     * Creates an immutable audit event.
     *
     * @param timestamp event timestamp
     * @param actor actor responsible for the event
     * @param eventType stable event type
     * @param data event data, or {@code null} to represent a JSON {@code null} event value
     */
    public AuditEvent(Instant timestamp, String actor, String eventType, Map<String, Object> data) {
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp");
        this.actor = requireNonBlank(actor, "actor");
        this.eventType = requireNonBlank(eventType, "eventType");
        this.data = data == null
                ? null
                : copyMap(data, "data", new IdentityHashMap<>());
    }

    public Instant timestamp() {
        return timestamp;
    }

    public String actor() {
        return actor;
    }

    public String eventType() {
        return eventType;
    }

    /**
     * Returns immutable event data, or {@code null} when this event represents JSON null data.
     */
    public Map<String, Object> data() {
        return data;
    }

    private static String requireNonBlank(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }

    private static Map<String, Object> copyMap(
            Map<?, ?> source,
            String path,
            IdentityHashMap<Object, Boolean> ancestors
    ) {
        enterContainer(source, path, ancestors);
        try {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : source.entrySet()) {
                Object key = entry.getKey();
                if (!(key instanceof String)) {
                    throw new IllegalArgumentException(path + " contains a non-string key");
                }
                String stringKey = (String) key;
                copy.put(stringKey, copyValue(entry.getValue(), path + "." + stringKey, ancestors));
            }
            return Collections.unmodifiableMap(copy);
        } finally {
            ancestors.remove(source);
        }
    }

    private static List<Object> copyList(
            List<?> source,
            String path,
            IdentityHashMap<Object, Boolean> ancestors
    ) {
        enterContainer(source, path, ancestors);
        try {
            List<Object> copy = new ArrayList<>(source.size());
            for (int i = 0; i < source.size(); i++) {
                copy.add(copyValue(source.get(i), path + "[" + i + "]", ancestors));
            }
            return Collections.unmodifiableList(copy);
        } finally {
            ancestors.remove(source);
        }
    }

    private static Object copyValue(
            Object value,
            String path,
            IdentityHashMap<Object, Boolean> ancestors
    ) {
        if (value == null || value instanceof String || value instanceof Boolean
                || value instanceof Byte || value instanceof Short
                || value instanceof Integer || value instanceof Long) {
            return value;
        }
        if (value instanceof Map<?, ?>) {
            return copyMap((Map<?, ?>) value, path, ancestors);
        }
        if (value instanceof List<?>) {
            return copyList((List<?>) value, path, ancestors);
        }
        throw new IllegalArgumentException(
                path + " contains unsupported value type: " + value.getClass().getName()
        );
    }

    private static void enterContainer(
            Object container,
            String path,
            IdentityHashMap<Object, Boolean> ancestors
    ) {
        if (ancestors.put(container, Boolean.TRUE) != null) {
            throw new IllegalArgumentException(path + " contains a cyclic structure");
        }
    }
}
