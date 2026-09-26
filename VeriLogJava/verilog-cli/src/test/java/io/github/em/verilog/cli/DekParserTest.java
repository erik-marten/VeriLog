package io.github.em.verilog.cli;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

final class DekParserTest {

    @Test
    void should_parse_dek_hex_when_valid_64_hex_chars() throws Exception {
        String hex = "00".repeat(32); // 32 bytes -> 64 hex chars
        byte[] dek = DekParser.parseDek(Map.of("dek-hex", hex));
        assertNotNull(dek);
        assertEquals(32, dek.length);
        assertEquals(0, dek[0]);
    }

    @Test
    void should_parse_dek_b64_when_valid_32_bytes() throws Exception {
        byte[] raw = new byte[32];
        raw[0] = 7;
        String b64 = Base64.getEncoder().encodeToString(raw);

        byte[] dek = DekParser.parseDek(Map.of("dek-b64", b64));
        assertNotNull(dek);
        assertEquals(32, dek.length);
        assertEquals(7, dek[0]);
    }

    @Test
    void should_throw_when_dek_hex_is_not_32_bytes() {
        // 31 bytes -> 62 hex chars
        String hex = "00".repeat(31);

        assertThrows(IllegalArgumentException.class,
                () -> DekParser.parseDek(Map.of("dek-hex", hex)));
    }

    @Test
    void should_throw_when_dek_b64_is_not_32_bytes() {
        byte[] raw = new byte[31];
        String b64 = Base64.getEncoder().encodeToString(raw);

        assertThrows(IllegalArgumentException.class,
                () -> DekParser.parseDek(Map.of("dek-b64", b64)));
    }

    @Test
    void should_return_null_when_no_dek_flag_provided() throws Exception {
        assertEquals(DekParser.parseDek(Map.of()).length, 0);
    }
}