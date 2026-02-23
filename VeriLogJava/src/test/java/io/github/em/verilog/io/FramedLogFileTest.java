package io.github.em.verilog.io;

import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.errors.VeriLogException;
import io.github.em.verilog.errors.VeriLogIoException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class FramedLogFileTest {

    @TempDir
    Path tempDir;

    @Test
    void should_create_header_and_maintain_next_seq_when_reopened() throws Exception {
        Path dir = Files.createTempDirectory("verilog-test");
        Path file = dir.resolve("log.vlog");

        byte[] dek = new byte[32];
        new SecureRandom().nextBytes(dek);

        try (FramedLogFile f = FramedLogFile.openOrCreate(file, dek, "aad")) {
            assertEquals(1, f.nextSeq());
            f.appendEncryptedJson(FramedLogFile.TYPE_LOG, 1, "{\"a\":1}".getBytes());
            f.appendEncryptedJson(FramedLogFile.TYPE_LOG, 2, "{\"a\":2}".getBytes());
            f.flush(true);
            assertEquals(3, f.nextSeq());
        }

        try (FramedLogFile f2 = FramedLogFile.openOrCreate(file, dek, "aad")) {
            assertEquals(3, f2.nextSeq());
            f2.appendEncryptedJson(FramedLogFile.TYPE_LOG, 3, "{\"a\":3}".getBytes());
            f2.flush(true);
            assertEquals(4, f2.nextSeq());
        }
    }

    @Test
    void should_truncate_partial_frame_on_reopen() throws Exception {
        Path dir = Files.createTempDirectory("verilog-test");
        Path file = dir.resolve("log.vlog");

        byte[] dek = CryptoUtil.sha256Utf8("dek");
        try (FramedLogFile f = FramedLogFile.openOrCreate(file, dek, "aad")) {
            f.appendEncryptedJson(FramedLogFile.TYPE_LOG, 1, "{\"a\":1}".getBytes());
            f.appendEncryptedJson(FramedLogFile.TYPE_LOG, 2, "{\"a\":2}".getBytes());
            f.appendEncryptedJson(FramedLogFile.TYPE_LOG, 3, "{\"a\":3}".getBytes());
            f.flush(true);
        }

        long size = Files.size(file);
        try (var ch = java.nio.channels.FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            // Truncate into the middle of the last frame (seq=3)
            ch.truncate(size - 7);
        }

        try (FramedLogFile f2 = FramedLogFile.openOrCreate(file, dek, "aad")) {
            // after recovery we keep seq=1 and seq=2 -> next is 3
            assertEquals(3, f2.nextSeq(), "Should recover to seq=3 (max=2) after truncating partial last frame");
        }
    }

    @Test
    void should_throw_io_exception_when_path_points_to_directory() throws Exception {
        // Arrange: create a directory and pass it as "file path"
        Path dirAsFile = tempDir.resolve("not_a_file");
        Files.createDirectory(dirAsFile);

        byte[] dek32 = new byte[32];
        String aad = "test-aad";

        // Act
        VeriLogIoException ex = assertThrows(
                VeriLogIoException.class,
                () -> FramedLogFile.openOrCreate(dirAsFile, dek32, aad)
        );

        // Assert: cause preserved
        assertNotNull(ex.getCause());
        assertTrue(ex.getCause() instanceof IOException);

        // Category
        assertEquals(VeriLogException.Category.IO, ex.getCategory());

        // Message key
        assertEquals("io.write_failed", ex.getMessageKey());
    }

    @Test
    void should_close_f_when_non_null() throws Exception {
        FramedLogFile f = mock(FramedLogFile.class);
        IOException e = new IOException("init failed");

        FramedLogFile.closeOnInitFailure(f, e);

        verify(f).close();
        assertEquals(0, e.getSuppressed().length, "no suppressed exception expected when close succeeds");
    }

    @Test
    void should_add_suppressed_when_close_throws() throws Exception {
        FramedLogFile f = mock(FramedLogFile.class);
        IOException init = new IOException("init failed");
        IOException closeEx = new IOException("close failed");

        doThrow(closeEx).when(f).close();

        FramedLogFile.closeOnInitFailure(f, init);

        assertEquals(1, init.getSuppressed().length);
        assertSame(closeEx, init.getSuppressed()[0], "close exception should be suppressed on init exception");
    }

    @Test
    void should_do_nothing_when_f_is_null() {
        IOException init = new IOException("init failed");
        FramedLogFile.closeOnInitFailure(null, init);
        assertEquals(0, init.getSuppressed().length);
    }
}