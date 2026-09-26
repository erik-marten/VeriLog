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

import ch.qos.logback.classic.spi.ILoggingEvent;
import org.slf4j.event.KeyValuePair;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Resolves explicitly supplied audit semantics from Logback metadata.
 *
 * <p>The {@code verilog.*} namespace is reserved for VeriLog integration metadata. This
 * resolver defines only {@code verilog.eventType}.
 */
final class LogbackAuditSemanticsResolver {

    private static final String EVENT_TYPE_KEY = "verilog.eventType";

    Optional<String> resolveEventType(ILoggingEvent event) {
        Objects.requireNonNull(event, "event");

        List<KeyValuePair> keyValuePairs = event.getKeyValuePairs();
        if (keyValuePairs == null || keyValuePairs.isEmpty()) {
            return Optional.empty();
        }

        Object eventType = null;
        boolean found = false;
        for (KeyValuePair keyValuePair : keyValuePairs) {
            if (keyValuePair != null && EVENT_TYPE_KEY.equals(keyValuePair.key)) {
                if (found) {
                    throw new IllegalArgumentException(EVENT_TYPE_KEY + " must occur at most once");
                }
                found = true;
                eventType = keyValuePair.value;
            }
        }

        if (!found) {
            return Optional.empty();
        }
        Objects.requireNonNull(eventType, EVENT_TYPE_KEY + " value");
        if (!(eventType instanceof String)) {
            throw new IllegalArgumentException(EVENT_TYPE_KEY + " value must be a String");
        }

        String value = (String) eventType;
        if (value.isBlank()) {
            throw new IllegalArgumentException(EVENT_TYPE_KEY + " value must not be blank");
        }
        return Optional.of(value);
    }
}
