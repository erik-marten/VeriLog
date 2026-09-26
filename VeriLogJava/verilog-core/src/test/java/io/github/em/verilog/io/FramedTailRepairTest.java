package io.github.em.verilog.io;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class FramedTailRepairTest {
    @TempDir Path directory;

    @Test
    void maximum_header_length_locates_and_removes_partial_frame_length() throws Exception {
        VlogHeaderCodec codec = new VlogHeaderCodec();
        int jsonOverhead = codec.encode("x", Instant.EPOCH).length - 8 - 1;
        byte[] header = codec.encode("x".repeat(0xffff - jsonOverhead), Instant.EPOCH);
        assertEquals(8 + 0xffff, header.length);
        Path active = directory.resolve("active.vlog");
        Files.write(active, header);
        Files.write(active, new byte[]{1, 2}, StandardOpenOption.APPEND);

        assertEquals(2, FramedTailRepair.truncateIncompleteTail(active));
        assertArrayEquals(header, Files.readAllBytes(active));
        assertEquals(0, FramedTailRepair.truncateIncompleteTail(active));
    }

    @Test
    void preserves_complete_frames_when_removing_partial_payload() throws Exception {
        byte[] header = new VlogHeaderCodec().encode("VeriLog|v1", Instant.EPOCH);
        byte[] complete = ByteBuffer.allocate(4 + 33).putInt(33).put(new byte[33]).array();
        byte[] partial = ByteBuffer.allocate(4 + 5).putInt(100).put(new byte[5]).array();
        Path active = directory.resolve("active.vlog");
        Files.write(active, header);
        Files.write(active, complete, StandardOpenOption.APPEND);
        Files.write(active, partial, StandardOpenOption.APPEND);

        assertEquals(partial.length, FramedTailRepair.truncateIncompleteTail(active));
        byte[] expected = Arrays.copyOf(header, header.length + complete.length);
        System.arraycopy(complete, 0, expected, header.length, complete.length);
        assertArrayEquals(expected, Files.readAllBytes(active));
    }

    @Test
    void rejects_invalid_or_incomplete_headers_without_mutating_them() throws Exception {
        byte[] valid = new VlogHeaderCodec().encode("VeriLog|v1", Instant.EPOCH);
        byte[] badMagic = valid.clone();
        badMagic[0] = 'X';
        byte[] badVersion = valid.clone();
        badVersion[4] = 2;
        byte[] incomplete = Arrays.copyOf(valid, valid.length - 1);
        byte[][] cases = {badMagic, badVersion, incomplete};

        for (int i = 0; i < cases.length; i++) {
            Path active = directory.resolve("invalid-" + i + ".vlog");
            Files.write(active, cases[i]);
            assertThrows(IOException.class, () -> FramedTailRepair.truncateIncompleteTail(active));
            assertArrayEquals(cases[i], Files.readAllBytes(active));
        }
    }
}
