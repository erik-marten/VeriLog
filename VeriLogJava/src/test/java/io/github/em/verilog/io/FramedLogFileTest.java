package io.github.em.verilog.io;

import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.errors.VeriLogException;
import io.github.em.verilog.errors.VeriLogFormatException;
import io.github.em.verilog.errors.VeriLogIoException;
import io.github.em.verilog.reader.FramedFileReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedConstruction;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
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
            // after recovery keep seq=1 and seq=2 -> next is 3
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


    @Test
    void next_should_throw_NoSuchElementException_when_no_more_frames() {
        try (MockedConstruction<FramedFileReader> mocked =
                     mockConstruction(FramedFileReader.class, (mock, ctx) -> {
                         when(mock.readNextFrame(false)).thenReturn(null); // EOF
                     })) {

            FramedFileReader r = new FramedFileReader(Path.of("dummy.vlog"));
            var it = r.frames(false).iterator();

            assertFalse(it.hasNext());
            assertThrows(java.util.NoSuchElementException.class, it::next);
        } catch (VeriLogIoException e) {
            throw new RuntimeException(e);
        } catch (VeriLogFormatException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void should_throw_when_dek_is_null() {
        Path file = tempDir.resolve("log.vlog");

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> FramedLogFile.openOrCreate(file, null, "aad")
        );

        assertEquals("DEK must be 32 bytes", ex.getMessage());
    }

    @Test
    void should_throw_when_dek_length_is_not_32() {
        Path file = tempDir.resolve("log.vlog");

        byte[] wrongDek = new byte[16]; // invalid length

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> FramedLogFile.openOrCreate(file, wrongDek, "aad")
        );

        assertEquals("DEK must be 32 bytes", ex.getMessage());
    }

    @Test
    void should_handle_eof_without_frames() throws Exception {
        Path file = tempDir.resolve("empty-after-header.vlog");

        byte[] dek = new byte[32];

        // Create file (writes only header)
        try (FramedLogFile f = FramedLogFile.openOrCreate(file, dek, "aad")) {
            // no frames appended
        }

        // Reopen → scanNextSeq() sees EOF immediately
        try (FramedLogFile f2 = FramedLogFile.openOrCreate(file, dek, "aad")) {
            assertEquals(1, f2.nextSeq());
        }
    }

    @Test
    void should_handle_partial_length_prefix() throws Exception {
        Path file = tempDir.resolve("partial-length.vlog");

        byte[] dek = new byte[32];

        try (FramedLogFile f = FramedLogFile.openOrCreate(file, dek, "aad")) {
            f.appendEncryptedJson(FramedLogFile.TYPE_LOG, 1, "{\"a\":1}".getBytes());
            f.flush(true);
        }

        // Corrupt: leave only 2 bytes of a new length prefix
        try (var ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            ch.position(ch.size());
            ch.write(ByteBuffer.wrap(new byte[]{0x00, 0x01})); // only 2 bytes
        }

        // Reopen triggers scanNextSeq -> r < 4
        try (FramedLogFile f2 = FramedLogFile.openOrCreate(file, dek, "aad")) {
            assertEquals(2, f2.nextSeq());
        }
    }

    @Test
    void should_break_on_payload_too_small() throws Exception {
        Path file = tempDir.resolve("payload-too-small.vlog");
        byte[] dek = new byte[32];

        // Create valid file (header only)
        try (FramedLogFile f = FramedLogFile.openOrCreate(file, dek, "aad")) {
            // no frames
        }

        // Append invalid length prefix (payloadLen = 5 < 9)
        try (var ch = FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ByteBuffer buf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            buf.putInt(5);  // invalid payload length
            buf.flip();
            ch.write(buf);
        }

        // Reopen → scanNextSeq() should break
        try (FramedLogFile f2 = FramedLogFile.openOrCreate(file, dek, "aad")) {
            assertEquals(1, f2.nextSeq()); // no valid frames found
        }
    }

    @Test
    void should_break_on_payload_too_large() throws Exception {
        Path file = tempDir.resolve("payload-too-large.vlog");
        byte[] dek = new byte[32];

        try (FramedLogFile f = FramedLogFile.openOrCreate(file, dek, "aad")) {
            // no frames
        }

        // Append insane payload length (100 MB)
        try (var ch = FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ByteBuffer buf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            buf.putInt(100 * 1024 * 1024); // 100 MB > MAX_PAYLOAD_LEN
            buf.flip();
            ch.write(buf);
        }

        try (FramedLogFile f2 = FramedLogFile.openOrCreate(file, dek, "aad")) {
            assertEquals(1, f2.nextSeq());
        }
    }
}



