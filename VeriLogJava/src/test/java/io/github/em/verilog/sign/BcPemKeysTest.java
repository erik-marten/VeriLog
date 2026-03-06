package io.github.em.verilog.sign;

import io.github.em.verilog.errors.VeriLogFormatException;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.Reader;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;

class BcPemKeysTest {

    private static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    @Test
    void should_read_pkcs8_private_key_der_from_pem() throws VeriLogFormatException {
        byte[] der = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        String pem = pem("PRIVATE KEY", der);

        byte[] got = BcPemKeys.readPkcs8PrivateKeyDer(pem);
        assertArrayEquals(der, got);
    }

    @Test
    void should_read_spki_public_key_der_from_pem() throws VeriLogFormatException {
        byte[] der = new byte[] { 9, 10, 11, 12, 13 };
        String pem = pem("PUBLIC KEY", der);

        byte[] got = BcPemKeys.readSpkiPublicKeyDer(pem);
        assertArrayEquals(der, got);
    }

    @Test
    void should_throw_exception_when_pem_is_empty() {
        VeriLogFormatException ex = assertThrows(VeriLogFormatException.class, () -> BcPemKeys.readPkcs8PrivateKeyDer(""));
        assertNotNull(ex.getMessage());
    }

    @Test
    void should_wrap_io_exception_as_read_failed() {
        Reader failingReader = new Reader() {
            @Override
            public int read(char[] cbuf, int off, int len) throws IOException {
                throw new IOException("boom");
            }

            @Override
            public void close() {
                // nothing to close
            }
        };

        VeriLogFormatException ex = assertThrows(
                VeriLogFormatException.class,
                () -> BcPemKeys.readPkcs8PrivateKeyDer(failingReader)
        );

        assertEquals("format.pem.read_failed", ex.getMessageKey());
        assertNotNull(ex.getCause());
        assertTrue(ex.getCause() instanceof IOException);
    }

    @Test
    void should_wrap_runtime_exception_as_read_failed() {
        Reader failingReader = new Reader() {
            @Override
            public int read(char[] cbuf, int off, int len) {
                throw new RuntimeException("boom");
            }

            @Override
            public void close() {
                // nothing to close
            }
        };

        VeriLogFormatException ex = assertThrows(
                VeriLogFormatException.class,
                () -> BcPemKeys.readPkcs8PrivateKeyDer(failingReader)
        );

        assertEquals("format.pem.read_failed", ex.getMessageKey());
        assertNotNull(ex.getCause());
        assertTrue(ex.getCause() instanceof RuntimeException);
    }

}