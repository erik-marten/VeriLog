package io.github.em.verilog.reader;

import io.github.em.verilog.errors.VeriLogIoException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class FramedFileReaderTest {
    @Test
    void should_throw_verilog_io_exception_when_close_fails() throws Exception {
        FileChannel ch = mock(FileChannel.class);
        doThrow(new IOException("boom")).when(ch).close();

        FramedFileReader r = new FramedFileReader(ch, new byte[0], 0, Path.of("foo"));

        VeriLogIoException ex = assertThrows(VeriLogIoException.class, r::close);

        assertNotNull(ex.getCause());
        assertEquals("Failed to close log file foo", ex.getMessage());
        assertTrue(ex.getCause() instanceof IOException);
        assertEquals("io.close_failed", ex.getMessageKey());
    }

    @Test
    void should_return_null_when_trailing_partial_and_tolerated() throws Exception {
        FileChannel ch = mock(FileChannel.class);

        // First read gives 2 bytes (partial), then EOF
        when(ch.read(any(ByteBuffer.class))).thenReturn(2).thenReturn(-1);

        FramedFileReader r = new FramedFileReader(ch, new byte[0], 0, Path.of("foo"));

        assertNull(r.readNextFrame(true));
    }

    @Test
    void should_throw_verilog_io_exception_when_trailing_partial_not_tolerated() throws Exception {
        FileChannel ch = mock(FileChannel.class);
        when(ch.read(any(ByteBuffer.class))).thenReturn(2).thenReturn(-1);

        FramedFileReader r = new FramedFileReader(ch, new byte[0], 0,Path.of("foo"));

        VeriLogIoException ex = assertThrows(
                VeriLogIoException.class,
                () -> r.readNextFrame(false)
        );

        assertEquals("io.partial_frame_length", ex.getMessageKey());
    }
}
