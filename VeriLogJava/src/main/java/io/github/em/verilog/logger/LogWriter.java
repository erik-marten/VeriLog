package io.github.em.verilog.logger;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.em.verilog.audit.HashChainState;
import io.github.em.verilog.audit.SignedEntryFactory;
import io.github.em.verilog.io.FramedLogFile;

import java.util.concurrent.CountDownLatch;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

final class LogWriter implements Runnable {

    private final VeriLoggerConfig cfg;
    private final BlockingQueue<LogEvent> queue;
    private final LoggerMetrics metrics;

    private final ObjectMapper om = new ObjectMapper();
    private final AtomicBoolean closed;
    private final AtomicBoolean faulted;

    private final FlushPolicy flushPolicy;
    private final RotationPolicy rotationPolicy;

    // writer-owned state
    private volatile FramedLogFile file;
    private volatile long bytesWrittenCurrent;
    private volatile long lastFlushMs;
    private int sinceFlush;
    private long nextSeq;

    private final SignedEntryFactory signedFactory = new SignedEntryFactory();
    private final HashChainState chain = HashChainState.fresh();
    private final CountDownLatch terminated;

    LogWriter(
            VeriLoggerConfig cfg,
            BlockingQueue<LogEvent> queue,
            LoggerMetrics metrics,
            AtomicBoolean closed,
            AtomicBoolean faulted,
            CountDownLatch terminated
    ) throws IOException {
        this.cfg = cfg;
        this.queue = queue;
        this.metrics = metrics;
        this.closed = closed;
        this.faulted = faulted;

        this.flushPolicy = new FlushPolicy(cfg.flushEveryN, cfg.flushEveryMs, cfg.fsyncOnFlush);
        this.rotationPolicy = new RotationPolicy(cfg.rotateBytes, cfg.filePrefix);
        this.terminated = terminated;

        Path current = currentPath();
        Files.createDirectories(cfg.logDir);

        if (cfg.rotateOnStartup && Files.exists(current) && Files.size(current) > 0) {
            rotateExistingOnStartup(current);
        }

// Create file with 0600 only if it doesn't exist yet (POSIX only)
        ensureFileExistsWith0600IfPossible(current);

        this.file = FramedLogFile.openOrCreate(current, cfg.encryptionKey32, cfg.aadPrefix);
        this.nextSeq = file.nextSeq();
        this.bytesWrittenCurrent = Files.exists(current) ? Files.size(current) : 0;
        this.lastFlushMs = System.currentTimeMillis();
    }

    @Override
    public void run() {
        try {
            while (true) {
                LogEvent ev = null;
                try {
                    ev = queue.poll(50, TimeUnit.MILLISECONDS);
                } catch (InterruptedException ignored) {
                    // shutdown is handled via 'closed' + POISON
                }

                if (ev != null) {
                    if (ev == LogEvent.POISON) {
                        break; // Stop-Signal
                    }
                    writeOne(ev);
                }

                maybeFlush();

                if (bytesWrittenCurrent >= rotationPolicy.rotateBytes) rotate();

                // when close() and queue empty terminate cleanly
                if (closed.get() && queue.isEmpty()) break;
            }

            // after stop drain rest of events
            LogEvent ev;
            while ((ev = queue.poll()) != null) {
                if (ev == LogEvent.POISON) continue;
                writeOne(ev);
            }

            file.flush(true);

        } catch (Throwable t) {
            faulted.set(true);
            try {
                file.flush(true);
            } catch (Exception ignored) {
            }
        } finally {
            try {
                if (file != null) file.close();
            } catch (Exception ignored) {
            }
            terminated.countDown();
        }
    }

    void flushAndCloseBestEffort() {
        try {
            FramedLogFile f = this.file;
            if (f != null) {
                f.flush(true);
                f.close();
            }
        } catch (Exception ignored) {
        }
    }

    private void writeOne(LogEvent ev) throws IOException {
        try {
            // Build SignedEntry JSON (plaintext before encryption)
            byte[] signedEntryJson = signedFactory.buildSignedEntryJsonUtf8(
                    chain,
                    cfg.signer,
                    cfg.actor,
                    ev.level.name(),
                    Map.of(
                            "msg", ev.message,
                            "fields", ev.fields
                    ),
                    ev.ts
            );

            long seqForFrame = chain.nextSeq() - 1; //  just allocated it
            file.appendEncryptedJson(FramedLogFile.TYPE_LOG, seqForFrame, signedEntryJson);

            metrics.incWritten();
            bytesWrittenCurrent += estimateFrameBytes(signedEntryJson.length);
            sinceFlush++;

        } catch (Exception e) {
            faulted.set(true);
            try {
                file.flush(true);
            } catch (Exception ignored) {
            }
            throw new IOException("Failed to build/sign/encrypt log entry", e);
        }
    }

    private void maybeFlush() throws IOException {
        long now = System.currentTimeMillis();
        if (sinceFlush >= flushPolicy.flushEveryN || (now - lastFlushMs) >= flushPolicy.flushEveryMs) {
            file.flush(flushPolicy.fsyncOnFlush);
            sinceFlush = 0;
            lastFlushMs = now;
        }
    }

    private void rotate() throws IOException {
        file.flush(true);
        file.close();

        Path cur = currentPath();
        Path rotated = rotationPolicy.rotatedPath(cfg.logDir);

        try {
            Files.move(cur, rotated, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(cur, rotated, StandardCopyOption.REPLACE_EXISTING);
        }

        this.file = FramedLogFile.openOrCreate(cur, cfg.encryptionKey32, cfg.aadPrefix);
        this.nextSeq = file.nextSeq();
        this.bytesWrittenCurrent = Files.size(cur);
        this.sinceFlush = 0;
        this.lastFlushMs = System.currentTimeMillis();
    }

    private void rotateExistingOnStartup(Path current) throws IOException {
        Path rotated = rotationPolicy.rotatedPath(cfg.logDir);

        try {
            Files.move(current, rotated, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(current, rotated, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void ensureFileExistsWith0600IfPossible(Path file) throws IOException {
        if (Files.exists(file)) return;

        try {
            var perms = PosixFilePermissions.fromString("rw-------");
            Files.createFile(file, PosixFilePermissions.asFileAttribute(perms));
        } catch (UnsupportedOperationException e) {
            // Non-POSIX FS (e.g., Windows): fall back to normal create
            Files.createFile(file);
        } catch (FileAlreadyExistsException ignored) {
            // race: someone created it between exists() and createFile()
        }
    }

    private Path currentPath() {
        return cfg.logDir.resolve(cfg.currentFileName);
    }

    private FramedLogFile openOrResumeCurrentFile() throws IOException {
        return FramedLogFile.openOrCreate(currentPath(), cfg.encryptionKey32, cfg.aadPrefix);
    }

    private long estimateFrameBytes(int plaintextLen) {
        return 4L + 1 + 8 + 24 + plaintextLen + 16;
    }
}