/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.logger;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.em.verilog.audit.HashChainState;
import io.github.em.verilog.audit.SignedEntryFactory;
import io.github.em.verilog.errors.VeriLogCryptoException;
import io.github.em.verilog.errors.VeriLogIoException;
import io.github.em.verilog.io.FramedLogFile;

import java.util.concurrent.CountDownLatch;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

final class LogWriter implements Runnable {

    private final VeriLoggerConfig cfg;
    private final BlockingQueue<LogEvent> queue;
    private final LoggerMetrics metrics;

    private final AtomicBoolean closed;
    private final AtomicBoolean faulted;

    private final FlushPolicy flushPolicy;
    private final RotationPolicy rotationPolicy;

    // writer-owned state
    private volatile FramedLogFile file;
    private long bytesWrittenCurrent;
    private volatile long lastFlushMs;
    private int sinceFlush;

    private final SignedEntryFactory signedFactory = new SignedEntryFactory();
    private final HashChainState chain = HashChainState.fresh();
    private final CountDownLatch terminated;

    private final AtomicReference<Throwable> firstFailure = new AtomicReference<>();

    LogWriter(
            VeriLoggerConfig cfg,
            BlockingQueue<LogEvent> queue,
            LoggerMetrics metrics,
            AtomicBoolean closed,
            AtomicBoolean faulted,
            CountDownLatch terminated
    ) throws VeriLogIoException {
        this.cfg = cfg;
        this.queue = queue;
        this.metrics = metrics;
        this.closed = closed;
        this.faulted = faulted;

        this.flushPolicy = new FlushPolicy(cfg.flushEveryN, cfg.flushEveryMs, cfg.fsyncOnFlush);
        this.rotationPolicy = new RotationPolicy(cfg.rotateBytes, cfg.filePrefix);
        this.terminated = terminated;

        try {
            Path current = currentPath();
            Files.createDirectories(cfg.logDir);

            if (cfg.rotateOnStartup && Files.exists(current) && Files.size(current) > 0) {
                rotateExistingOnStartup(current);
            }

// Create file with 0600 only if it doesn't exist yet (POSIX only)
            ensureFileExistsWith0600IfPossible(current);
            this.file = FramedLogFile.openOrCreate(current, cfg.encryptionKey32, cfg.aadPrefix);
            this.bytesWrittenCurrent = Files.exists(current) ? Files.size(current) : 0;
            this.lastFlushMs = System.currentTimeMillis();
        } catch (IOException e) {
            throw new VeriLogIoException("io.create_failed", e.getCause());
        }
    }

    @Override
    public void run() {
        try {
            mainLoop();
            drainRemaining();
            flushFinal();
        } catch (Throwable t) {
            // This is the writer thread boundary. The logger must be marked as faulted
            // even for serious JVM Errors to avoid silent thread death.
            onFault(t);
        } finally {
            closeAndSignalTermination();
        }
    }

    private void mainLoop() throws VeriLogIoException, IOException {
        while (true) {
            LogEvent ev = pollEvent();

            if (ev == LogEvent.POISON) break;

            if (ev != null) {
                writeOne(ev);
            }

            afterTick();

            if (shouldTerminate()) break;
        }
    }

    private LogEvent pollEvent() {
        try {
            return queue.poll(50, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            return LogEvent.POISON;
        }
    }

    private void afterTick() throws IOException, VeriLogIoException {
        maybeFlush();
        if (shouldRotate()) rotate();
    }

    private boolean shouldRotate() {
        return bytesWrittenCurrent >= rotationPolicy.rotateBytes;
    }

    private boolean shouldTerminate() {
        return closed.get() && queue.isEmpty();
    }

    private void drainRemaining() throws IOException {
        LogEvent ev;
        while ((ev = queue.poll()) != null) {
            if (ev == LogEvent.POISON) continue;
            writeOne(ev);
        }
    }

    private void flushFinal() throws IOException {
        file.flush(true);
    }

    private void onFault(Throwable t) {
        faulted.set(true);
        firstFailure.compareAndSet(null, t);
        // Snapshot to avoid races with rotation/close and avoid NPE masking the root cause
        FramedLogFile f = this.file;
        if (f == null) return;
        try {
            f.flush(true);
        } catch (Exception ignored) {
            // Best-effort only: already faulted and don't want to hide the original failure.
        }
    }

    private void closeAndSignalTermination() {
        FramedLogFile f = this.file; // snapshot to avoid race

        try {
            if (f != null) {
                f.close();
            }
        } catch (Exception ignored) {
            // Best-effort close: terminating and must not mask the original failure.
        } finally {
            terminated.countDown();
        }
    }

    void flushAndCloseBestEffort() {
        FramedLogFile f = this.file; // snapshot to avoid race
        if (f == null) return;
        try {
            f.flush(true);
        } catch (Exception ignored) {
            // Best-effort: ignore flush failure during shutdown.
        }

        try {
            f.close();
        } catch (Exception ignored) {
            // Best-effort: ignore close failure during shutdown.
        }
    }

    private void writeOne(LogEvent ev) throws IOException {
        final FramedLogFile f = this.file; // snapshot (rotate/close safety)
        if (f == null) throw new IOException("Log file is not open");

        try {
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

            long seqForFrame = chain.nextSeq() - 1; // just allocated it
            f.appendEncryptedJson(FramedLogFile.TYPE_LOG, seqForFrame, signedEntryJson);

            metrics.incWritten();
            // Writer-thread confined state (only accessed from LogWriter.run())
            bytesWrittenCurrent += estimateFrameBytes(signedEntryJson.length);
            sinceFlush++;

        } catch (IOException ioe) {
            faulted.set(true);
            bestEffortFlush(f);
            throw ioe;

        } catch (VeriLogCryptoException | RuntimeException vce) {
            faulted.set(true);
            bestEffortFlush(f);
            throw new IOException("Failed to build/sign/encrypt log entry", vce);

        }
    }

    private static void bestEffortFlush(FramedLogFile f) {
        try {
            f.flush(true);
        } catch (Exception ignored) {
            // best-effort only; don't mask original failure
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

    protected void rotate() throws VeriLogIoException {
        try {
            file.flush(true);
            file.close();

            Path current = currentPath();
            Path rotated = rotationPolicy.rotatedPath(cfg.logDir);

            moveAtomicOrReplace(current, rotated);

            this.file = FramedLogFile.openOrCreate(current, cfg.encryptionKey32, cfg.aadPrefix);
            this.bytesWrittenCurrent = Files.size(current);
            this.sinceFlush = 0;
            this.lastFlushMs = System.currentTimeMillis();

        } catch (IOException e) {
            throw new VeriLogIoException("io.rotate_failed", e, currentPath().toString());
        }
    }

    private void rotateExistingOnStartup(Path current) throws IOException {
        Path rotated = rotationPolicy.rotatedPath(cfg.logDir);
        moveAtomicOrReplace(current, rotated);
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

    private long estimateFrameBytes(int plaintextLen) {
        return 4L + 1 + 8 + 24 + plaintextLen + 16;
    }

    static void moveAtomicOrReplace(Path src, Path dst) throws IOException {
        try {
            Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}