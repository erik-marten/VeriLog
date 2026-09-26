package io.github.em.verilog;

import io.github.em.verilog.errors.VeriLogFormatException;
import org.junit.jupiter.api.Test;

import static io.github.em.verilog.PemKeys.importEcPublicKeyFromPem;
import static org.junit.jupiter.api.Assertions.*;

public class PemKeysTest {

    @Test
    void should_throw_when_b64_is_empty() {

        VeriLogFormatException ex = assertThrows(VeriLogFormatException.class, () -> importEcPublicKeyFromPem(""));
        assertEquals(ex.getMessageKey(), "format.pem.empty");
    }

    @Test
    void should_throw_format_base64_invalid_when_pem_contains_invalid_base64() {
        String pem =
                "-----BEGIN PUBLIC KEY-----\n" +
                        "@@@@@\n" +
                        "-----END PUBLIC KEY-----";

        VeriLogFormatException ex = assertThrows(
                VeriLogFormatException.class,
                () -> importEcPublicKeyFromPem(pem)
        );
        assertEquals("format.pem.base64_invalid", ex.getMessageKey());
    }
    @Test
    void should_throw_public_key_invalid_for_valid_base64_but_invalid_der() {
        // "AQID" is valid Base64 => bytes [1,2,3]- not a valid X.509 public key DER
        String pem =
                "-----BEGIN PUBLIC KEY-----\n" +
                        "AQID\n" +
                        "-----END PUBLIC KEY-----";

        VeriLogFormatException ex = assertThrows(
                VeriLogFormatException.class,
                () -> importEcPublicKeyFromPem(pem)
        );

        assertEquals("format.pem.public_key_invalid", ex.getMessageKey());
    }
}
