package io.github.em.verilog.logger;

import io.github.em.verilog.errors.VeriLogIoException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Answers.CALLS_REAL_METHODS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

final class LogWriterTest {

    @TempDir
    Path tmp;

    @Test
    void should_write_event_and_close_when_poison_received() throws Exception {
        var queue = new LinkedBlockingQueue<LogEvent>();
        var closed = new AtomicBoolean(false);
        var faulted = new AtomicBoolean(false);
        var terminated = new CountDownLatch(1);

        var cfg = newConfig(tmp);
        var metrics = new LoggerMetrics(); // adjust if needed

        var writer = new LogWriter(cfg, queue, metrics, closed, faulted, terminated);
        var t = new Thread(writer, "logwriter-test");
        t.start();

        queue.put(new LogEvent(VeriLoggerConfig.Level.INFO, "hello", Map.of("k", "v"), Instant.now()));
        queue.put(LogEvent.POISON);

        assertTrue(terminated.await(3, TimeUnit.SECONDS), "writer should terminate");
        assertFalse(faulted.get(), "should not fault on normal write");

        Path current = tmp.resolve(cfg.currentFileName);
        assertTrue(Files.exists(current), "current log file should exist");
        assertTrue(Files.size(current) > 0, "file should not be empty");
    }

    @Test
    void should_rotate_when_bytes_exceed_threshold() throws Exception {
        var queue = new LinkedBlockingQueue<LogEvent>();
        var closed = new AtomicBoolean(false);
        var faulted = new AtomicBoolean(false);
        var terminated = new CountDownLatch(1);

        var cfg = newConfig(tmp);
        cfg.rotateBytes = 300; // small threshold to force rotation fast
        cfg.flushEveryN = 1;   // flush frequently for determinism
        cfg.flushEveryMs = 1;

        var metrics = new LoggerMetrics();

        var writer = new LogWriter(cfg, queue, metrics, closed, faulted, terminated);
        var t = new Thread(writer, "logwriter-rotate-test");
        t.start();

        // write enough events to exceed rotateBytes
        for (int i = 0; i < 50; i++) {
            queue.put(new LogEvent(VeriLoggerConfig.Level.INFO, "msg-" + i, Map.of("i", i), Instant.now()));
        }
        queue.put(LogEvent.POISON);

        assertTrue(terminated.await(5, TimeUnit.SECONDS), "writer should terminate");
        assertFalse(faulted.get(), "rotation path should not fault");

        // RotationPolicy naming is internal; assert by directory contents:
        // expects at least 2 files: current + at least one rotated
        try (var stream = Files.list(tmp)) {
            long count = stream.filter(Files::isRegularFile).count();
            assertTrue(count >= 2, "should create at least one rotated file plus current");
        }

        Path current = tmp.resolve(cfg.currentFileName);
        assertTrue(Files.exists(current), "current file should exist after rotation");
    }

    @Test
    void should_set_faulted_when_signing_fails_and_still_terminate() throws Exception {
        var queue = new LinkedBlockingQueue<LogEvent>();
        var closed = new AtomicBoolean(false);
        var faulted = new AtomicBoolean(false);
        var terminated = new CountDownLatch(1);

        var cfg = newConfig(tmp);
        cfg.signer = null; // provoke failure inside SignedEntryFactory.buildSignedEntryJsonUtf8

        var metrics = new LoggerMetrics();

        var writer = new LogWriter(cfg, queue, metrics, closed, faulted, terminated);
        var t = new Thread(writer, "logwriter-fault-test");
        t.start();

        queue.put(new LogEvent(VeriLoggerConfig.Level.INFO, "boom", Map.of(), Instant.now()));

        assertTrue(terminated.await(3, TimeUnit.SECONDS), "writer should terminate even on fault");
        assertTrue(faulted.get(), "faulted should be set on signing/encrypting failure");
    }

    @Test
    void should_fallback_to_replace_existing_when_atomic_move_not_supported() throws Exception {
        Path src = Path.of("a");
        Path dst = Path.of("b");

        try (MockedStatic<Files> files = mockStatic(Files.class)) {
            files.when(() -> Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE))
                    .thenThrow(new AtomicMoveNotSupportedException(src.toString(), dst.toString(), "nope"));

            files.when(() -> Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING))
                    .thenReturn(dst);

            LogWriter.moveAtomicOrReplace(src, dst);

            files.verify(() -> Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE), times(1));
            files.verify(() -> Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING), times(1));
        }
    }

    @Test
    void should_use_atomic_move_when_supported() throws Exception {
        Path src = Path.of("a");
        Path dst = Path.of("b");

        try (MockedStatic<Files> files = mockStatic(Files.class)) {
            files.when(() -> Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE))
                    .thenReturn(dst);

            LogWriter.moveAtomicOrReplace(src, dst);

            files.verify(() -> Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE), times(1));
            files.verifyNoMoreInteractions();
        }
    }

    @Test
    void should_wrap_ioexception_as_verilogioexception_when_rotate_fails() throws Exception {
        var queue = new LinkedBlockingQueue<LogEvent>();
        var closed = new AtomicBoolean(false);
        var faulted = new AtomicBoolean(false);
        var terminated = new CountDownLatch(1);

        var cfg = newConfig(tmp);
        cfg.rotateBytes = 1;
        var metrics = new LoggerMetrics();

        LogWriter writer = new LogWriter(cfg, queue, metrics, closed, faulted, terminated);

        // Ensures there is something to rotate
        queue.put(new LogEvent(VeriLoggerConfig.Level.INFO, "hello", Map.of(), Instant.now()));
        queue.put(LogEvent.POISON);
        new Thread(writer).start();
        assertTrue(terminated.await(3, java.util.concurrent.TimeUnit.SECONDS));

        // Re-open a fresh writer for direct rotate() call (simpler & isolated)
        writer = new LogWriter(cfg, new LinkedBlockingQueue<>(), new LoggerMetrics(),
                new AtomicBoolean(false), new AtomicBoolean(false), new CountDownLatch(1));

        try (MockedStatic<Files> files = mockStatic(Files.class, CALLS_REAL_METHODS)) {

            // Make Files.move fail regardless of options (ATOMIC_MOVE or REPLACE_EXISTING)
            files.when(() -> Files.move(any(Path.class), any(Path.class), any(CopyOption.class)))
                    .thenThrow(new IOException("boom"));

            VeriLogIoException ex = assertThrows(VeriLogIoException.class, writer::rotate);

            assertEquals("io.rotate_failed", ex.getMessageKey());
            assertTrue(ex.getMessage().contains(cfg.currentFileName));

            // Cause should be the original IOException
            assertTrue(ex.getCause() instanceof IOException);
        }
    }
    // ---- helpers ----

    private VeriLoggerConfig newConfig(Path dir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();

        var cfg = new VeriLoggerConfig();
        cfg.logDir = dir;
        cfg.currentFileName = "current.vlog";
        cfg.filePrefix = "verilog-";
        cfg.rotateOnStartup = false;

        cfg.rotateBytes = 1024 * 1024;
        cfg.flushEveryN = 10;
        cfg.flushEveryMs = 50;
        cfg.fsyncOnFlush = false;

        cfg.encryptionKey32 = new byte[32]; // test key
        cfg.aadPrefix = "test-aad";

        cfg.signer = new TestLogSigner(kp.getPrivate(), kp.getPublic());        cfg.actor = "test-actor";
        return cfg;
    }
}