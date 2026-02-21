package io.github.em.verilog.logger;

import java.time.Instant;
import java.util.Map;

final class LogEvent {
    final VeriLoggerConfig.Level level;
    final String message;
    final Map<String, Object> fields;
    final Instant ts;

    static final LogEvent POISON =
            new LogEvent(null, null, null, null);

    LogEvent(VeriLoggerConfig.Level level, String message, Map<String, Object> fields, Instant ts) {
        this.level = level;
        this.message = message;
        this.fields = fields;
        this.ts = ts;
    }
}