package io.github.em.verilog.logger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LoggerMetricsTest {

    @Test
    void should_increment_written_and_dropped_counters_when_inc_methods_are_called() {
        LoggerMetrics m = new LoggerMetrics();

        assertEquals(0, m.writtenCount());
        assertEquals(0, m.droppedCount());

        // increments are used internally
        m.incWritten();
        m.incWritten();
        m.incDropped();

        assertEquals(2, m.writtenCount());
        assertEquals(1, m.droppedCount());
    }
}