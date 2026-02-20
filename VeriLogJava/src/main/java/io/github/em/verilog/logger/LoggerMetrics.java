package io.github.em.verilog.logger;

import java.util.concurrent.atomic.AtomicLong;

public final class LoggerMetrics {
    private final AtomicLong dropped = new AtomicLong(0);
    private final AtomicLong written = new AtomicLong(0);

    void incDropped() { dropped.incrementAndGet(); }
    void incWritten() { written.incrementAndGet(); }

    public long droppedCount() { return dropped.get(); }
    public long writtenCount() { return written.get(); }
}