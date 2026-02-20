package io.github.em.verilog.io;

import io.github.em.verilog.CryptoUtil;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class FramedLogFileTest {

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
}