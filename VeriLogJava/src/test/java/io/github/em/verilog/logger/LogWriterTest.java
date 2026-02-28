package io.github.em.verilog.logger;

import io.github.em.verilog.errors.VeriLogIoException;
import io.github.em.verilog.io.FramedLogFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
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
import static org.mockito.Mockito.*;

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

    @Test
    void closeAndSignalTermination_should_countDown_even_if_close_throws() throws Exception {
        var queue = new LinkedBlockingQueue<LogEvent>();
        var closed = new AtomicBoolean(false);
        var faulted = new AtomicBoolean(false);
        var terminated = new CountDownLatch(1);

        var cfg = newConfig(tmp);
        var writer = new LogWriter(cfg, queue, new LoggerMetrics(), closed, faulted, terminated);

        // Replace private 'file' with a mock that throws on close
        FramedLogFile mockFile = mock(FramedLogFile.class);
        doThrow(new RuntimeException("close boom")).when(mockFile).close();
        setPrivateField(writer, "file", mockFile);

        // Invoke private closeAndSignalTermination()
        Method m = LogWriter.class.getDeclaredMethod("closeAndSignalTermination");
        m.setAccessible(true);
        m.invoke(writer);

        // The key assertion: finally block counted down even though close threw
        assertTrue(terminated.await(200, TimeUnit.MILLISECONDS), "terminated must be counted down in finally");
    }

    @Test
    void flushAndCloseBestEffort_should_close_even_if_flush_throws_and_swallow_exceptions() throws Exception {
        var queue = new LinkedBlockingQueue<LogEvent>();
        var closed = new AtomicBoolean(false);
        var faulted = new AtomicBoolean(false);
        var terminated = new CountDownLatch(1);

        var cfg = newConfig(tmp);
        var writer = new LogWriter(cfg, queue, new LoggerMetrics(), closed, faulted, terminated);

        FramedLogFile mockFile = mock(FramedLogFile.class);
        doThrow(new IOException("flush boom")).when(mockFile).flush(true);
        // close succeeds (or also make it throw to cover that catch too)
         doThrow(new IOException("close boom")).when(mockFile).close();
        setPrivateField(writer, "file", mockFile);
        assertDoesNotThrow(writer::flushAndCloseBestEffort);

        // Even though flush threw, close should still be attempted
        verify(mockFile, times(1)).flush(true);
        verify(mockFile, times(1)).close();
    }

    @Test
    void writeOne_should_throw_if_file_is_null() throws Exception {
        var queue = new LinkedBlockingQueue<LogEvent>();
        var closed = new AtomicBoolean(false);
        var faulted = new AtomicBoolean(false);
        var terminated = new CountDownLatch(1);

        var cfg = newConfig(tmp);
        var writer = new LogWriter(cfg, queue, new LoggerMetrics(), closed, faulted, terminated);

        // Force the snapshot branch to see f == null
        setPrivateField(writer, "file", null);

        Method writeOne = LogWriter.class.getDeclaredMethod("writeOne", LogEvent.class);
        writeOne.setAccessible(true);

        var ev = new LogEvent(VeriLoggerConfig.Level.INFO, "hello", Map.of(), Instant.now());

        Exception ex = assertThrows(Exception.class, () -> writeOne.invoke(writer, ev));
        // Reflection wraps the real exception
        Throwable cause = ex.getCause();
        assertTrue(cause instanceof IOException);
        assertEquals("Log file is not open", cause.getMessage());
    }

    @Test
    void writeOne_should_set_faulted_flush_and_rethrow_when_append_throws_ioexception() throws Exception {
        var queue = new LinkedBlockingQueue<LogEvent>();
        var closed = new AtomicBoolean(false);
        var faulted = new AtomicBoolean(false);
        var terminated = new CountDownLatch(1);

        var cfg = newConfig(tmp);
        var writer = new LogWriter(cfg, queue, new LoggerMetrics(), closed, faulted, terminated);

        FramedLogFile mockFile = mock(FramedLogFile.class);

        IOException boom = new IOException("append boom");
        doThrow(boom).when(mockFile).appendEncryptedJson(anyByte(), anyLong(), any(byte[].class));
        // bestEffortFlush should call flush(true)
        // (let flush succeed or throw- either way it’s swallowed by bestEffortFlush)
         doThrow(new IOException("flush boom")).when(mockFile).flush(true);
        setPrivateField(writer, "file", mockFile);

        Method writeOne = LogWriter.class.getDeclaredMethod("writeOne", LogEvent.class);
        writeOne.setAccessible(true);

        var ev = new LogEvent(VeriLoggerConfig.Level.INFO, "hello", Map.of(), Instant.now());

        Exception ex = assertThrows(Exception.class, () -> writeOne.invoke(writer, ev));
        Throwable cause = ex.getCause();

        // It should rethrow the SAME IOException instance (not wrap it)
        assertSame(boom, cause);

        assertTrue(faulted.get(), "faulted must be set on IOException path");
        verify(mockFile, times(1)).flush(true);
    }

    @Test
    void pollEvent_should_return_poison_and_preserve_interrupt_when_interrupted() throws Exception {
        var queue = new LinkedBlockingQueue<LogEvent>();
        var closed = new AtomicBoolean(false);
        var faulted = new AtomicBoolean(false);
        var terminated = new CountDownLatch(1);

        var cfg = newConfig(tmp);
        var writer = new LogWriter(cfg, queue, new LoggerMetrics(), closed, faulted, terminated);

        Method pollEvent = LogWriter.class.getDeclaredMethod("pollEvent");
        pollEvent.setAccessible(true);

        var resultRef = new java.util.concurrent.atomic.AtomicReference<LogEvent>();
        var interruptedAfter = new AtomicBoolean(false);
        var done = new CountDownLatch(1);

        Thread t = new Thread(() -> {
            try {
                Thread.currentThread().interrupt(); // force queue.poll(...) to throw InterruptedException
                LogEvent ev = (LogEvent) pollEvent.invoke(writer);
                resultRef.set(ev);
                interruptedAfter.set(Thread.currentThread().isInterrupted()); // should be true (re-interrupted)
            } catch (Exception e) {
                throw new AssertionError(e);
            } finally {
                done.countDown();
            }
        }, "pollEvent-interrupt-test");

        t.start();
        assertTrue(done.await(1, TimeUnit.SECONDS), "thread should finish");

        assertSame(LogEvent.POISON, resultRef.get(), "Interrupted poll should return POISON");
        assertTrue(interruptedAfter.get(), "pollEvent should re-interrupt the thread");
    }

    // ---- helpers ----

    private static void setPrivateField(Object target, String fieldName, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }

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