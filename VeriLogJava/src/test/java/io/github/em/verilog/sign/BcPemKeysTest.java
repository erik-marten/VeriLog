package io.github.em.verilog.sign;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class BcPemKeysTest {

    private static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    @Test
    void should_read_pkcs8_private_key_der_from_pem() {
        byte[] der = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        String pem = pem("PRIVATE KEY", der);

        byte[] got = BcPemKeys.readPkcs8PrivateKeyDer(pem);
        assertArrayEquals(der, got);
    }

    @Test
    void should_read_spki_public_key_der_from_pem() {
        byte[] der = new byte[] { 9, 10, 11, 12, 13 };
        String pem = pem("PUBLIC KEY", der);

        byte[] got = BcPemKeys.readSpkiPublicKeyDer(pem);
        assertArrayEquals(der, got);
    }

    @Test
    void should_throw_exception_when_pem_is_empty() {
        RuntimeException ex = assertThrows(RuntimeException.class, () -> BcPemKeys.readPkcs8PrivateKeyDer(""));
        assertNotNull(ex.getMessage());
    }
}