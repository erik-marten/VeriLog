package io.github.em.verilog.logger;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public final class VeriLogger implements Closeable {

    private final VeriLoggerConfig cfg;
    private final BlockingQueue<LogEvent> queue;
    private final BackpressureEnqueuer enqueuer;
    private final LoggerMetrics metrics = new LoggerMetrics();

    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean faulted = new AtomicBoolean(false);

    private final Thread writerThread;
    private final LogWriter writer;

    public static VeriLogger create(VeriLoggerConfig cfg) throws IOException {
        return new VeriLogger(cfg);
    }

    private VeriLogger(VeriLoggerConfig cfg) throws IOException {
        cfg.validate();
        this.cfg = cfg;

        this.queue = new ArrayBlockingQueue<>(cfg.queueCapacity);
        this.enqueuer = new BackpressureEnqueuer(cfg, queue);

        this.writer = new LogWriter(cfg, queue, metrics, closed, faulted);

        this.writerThread = new Thread(writer, "verilog-writer");
        this.writerThread.start();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try { close(); } catch (Exception ignored) {}
        }));
    }

    public void debug(String msg) { log(VeriLoggerConfig.Level.DEBUG, msg, Map.of()); }
    public void info(String msg)  { log(VeriLoggerConfig.Level.INFO, msg, Map.of()); }
    public void warn(String msg)  { log(VeriLoggerConfig.Level.WARN, msg, Map.of()); }
    public void error(String msg) { log(VeriLoggerConfig.Level.ERROR, msg, Map.of()); }

    public void log(VeriLoggerConfig.Level level, String message, Map<String, Object> fields) {
        Objects.requireNonNull(level, "level");
        Objects.requireNonNull(message, "message");
        if (fields == null) fields = Map.of();

        if (closed.get()) return;

        if (faulted.get() && cfg.faultMode == VeriLoggerConfig.FaultMode.FAIL_FAST) {
            throw new IllegalStateException("VeriLogger is faulted; refusing to accept logs.");
        }
        if (faulted.get()) {
            metrics.incDropped();
            return;
        }

        LogEvent ev = new LogEvent(level, message, fields, Instant.now());
        boolean ok = enqueuer.enqueue(ev);
        if (!ok) metrics.incDropped();
    }

    public long droppedCount() { return metrics.droppedCount(); }
    public long writtenCount() { return metrics.writtenCount(); }

    @Override
    public void close() throws IOException {
        close(Duration.ofSeconds(5).toMillis());
    }

    public void close(long timeoutMs) throws IOException {
        if (!closed.compareAndSet(false, true)) return;

        writerThread.interrupt();
        try {
            writerThread.join(timeoutMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            writer.flushAndCloseBestEffort();
        }
    }
}