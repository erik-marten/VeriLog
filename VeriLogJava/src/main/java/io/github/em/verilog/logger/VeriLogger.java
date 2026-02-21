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

    private final CountDownLatch terminated = new CountDownLatch(1);
    private final Thread writerThread;
    private final LogWriter writer;

    private Thread shutdownHook = null;

    public static VeriLogger create(VeriLoggerConfig cfg) throws IOException {
        return new VeriLogger(cfg);
    }

    private VeriLogger(VeriLoggerConfig cfg) throws IOException {
        cfg.validate();
        this.cfg = cfg;

        this.queue = new ArrayBlockingQueue<>(cfg.queueCapacity);
        this.enqueuer = new BackpressureEnqueuer(cfg, queue);

        this.writer = new LogWriter(cfg, queue, metrics, closed, faulted, terminated);

        this.writerThread = new Thread(writer, "verilog-writer");
        this.writerThread.setDaemon(false);
        this.writerThread.start();

        if (cfg.installShutdownHook) {
            this.shutdownHook = new Thread(() -> {
                try {
                    // Best-effort close with Timeout
                    close(cfg.shutdownTimeoutMs);
                } catch (Throwable ignored) {
                }
            }, "verilog-shutdown-hook");

            Runtime.getRuntime().addShutdownHook(this.shutdownHook);
        } else {
            this.shutdownHook = null;
        }
    }

    public void debug(String msg) {
        log(VeriLoggerConfig.Level.DEBUG, msg, Map.of());
    }

    public void info(String msg) {
        log(VeriLoggerConfig.Level.INFO, msg, Map.of());
    }

    public void warn(String msg) {
        log(VeriLoggerConfig.Level.WARN, msg, Map.of());
    }

    public void error(String msg) {
        log(VeriLoggerConfig.Level.ERROR, msg, Map.of());
    }

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

    public long droppedCount() {
        return metrics.droppedCount();
    }

    public long writtenCount() {
        return metrics.writtenCount();
    }

    @Override
    public void close() throws IOException {
        close(cfg.shutdownTimeoutMs);
    }

    public void close(long timeoutMs) throws IOException {
        if (!closed.compareAndSet(false, true)) return;

        // Hook entfernen, damit close nicht doppelt durch Hook + User läuft
        if (shutdownHook != null) {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);
            } catch (IllegalStateException ignored) {
                // JVM ist schon im Shutdown -> removeShutdownHook nicht erlaubt, ok.
            }
        }

        // 1) Poison Pill rein (oder queue.close())
        long deadline = System.currentTimeMillis() + Math.max(0, timeoutMs);
        boolean offered = false;
        while (!offered && System.currentTimeMillis() < deadline) {
            try {
                offered = queue.offer(LogEvent.POISON, 50, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        // 2) Warten bis Writer wirklich fertig ist
        long remaining = deadline - System.currentTimeMillis();
        if (remaining < 0) remaining = 0;

        try {
            boolean ok = terminated.await(remaining, TimeUnit.MILLISECONDS);
            if (!ok) {
                // Notfall: best effort und hart melden
                writer.flushAndCloseBestEffort();
                throw new IOException("Timed out waiting for writer thread to terminate.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            writer.flushAndCloseBestEffort();
            throw new IOException("Interrupted while waiting for writer to terminate.", e);
        }
    }
}