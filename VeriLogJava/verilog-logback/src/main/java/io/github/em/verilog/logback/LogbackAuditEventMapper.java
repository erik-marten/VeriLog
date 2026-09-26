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
import io.github.em.verilog.audit.AuditEvent;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Maps logging metadata with explicitly supplied audit semantics into an immutable event. */
final class LogbackAuditEventMapper {

    AuditEvent map(ILoggingEvent event, String actor, String eventType) {
        Objects.requireNonNull(event, "event");

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("message", event.getFormattedMessage());
        data.put("logger", event.getLoggerName());
        Level level = event.getLevel();
        data.put("level", level == null ? null : level.toString());
        data.put("thread", event.getThreadName());
        data.put("mdc", event.getMDCPropertyMap());

        // AuditEvent recursively copies the MDC map; no mutable framework state is retained.
        return new AuditEvent(event.getInstant(), actor, eventType, data);
    }
}
