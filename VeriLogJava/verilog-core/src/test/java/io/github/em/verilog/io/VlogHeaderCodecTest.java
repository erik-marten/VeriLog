package io.github.em.verilog.io;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class VlogHeaderCodecTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant CREATED_AT = Instant.parse("2026-01-02T03:04:05.123456789Z");

    @Test
    void encodes_binary_header_and_unicode_json() throws Exception {
        String aad = "caf\u00e9|\uD83D\uDD12";
        byte[] encoded = new VlogHeaderCodec().encode(aad, CREATED_AT);

        assertArrayEquals(new byte[]{'V', 'L', 'O', 'G'}, Arrays.copyOfRange(encoded, 0, 4));
        assertEquals(1, encoded[4]);
        assertEquals(0x01, encoded[5]);

        int jsonLength = ByteBuffer.wrap(encoded, 6, 2).order(ByteOrder.BIG_ENDIAN).getShort() & 0xFFFF;
        byte[] jsonBytes = Arrays.copyOfRange(encoded, 8, encoded.length);
        assertEquals(jsonBytes.length, jsonLength);
        assertEquals(8 + jsonLength, encoded.length);

        assertTrue(contains(jsonBytes, "caf\u00e9".getBytes(StandardCharsets.UTF_8)),
                "Unescaped Unicode is encoded as UTF-8");
        JsonNode json = MAPPER.readTree(jsonBytes);
        assertEquals(4, json.size());
        assertEquals(1, json.get("v").asInt());
        assertEquals("XChaCha20-Poly1305", json.get("alg").asText());
        assertEquals(aad, json.get("aad").asText());
        assertEquals(CREATED_AT.toString(), json.get("createdAt").asText());
    }

    @Test
    void fixed_inputs_produce_identical_bytes() throws Exception {
        VlogHeaderCodec codec = new VlogHeaderCodec();
        assertArrayEquals(codec.encode("same|aad", CREATED_AT), codec.encode("same|aad", CREATED_AT));
    }

    @Test
    void accepts_maximum_json_length_and_rejects_one_byte_more() throws Exception {
        VlogHeaderCodec codec = new VlogHeaderCodec();
        int emptyAadJsonLength = codec.encode("", CREATED_AT).length - 8;
        String maximumAad = "a".repeat(0xFFFF - emptyAadJsonLength);

        byte[] maximum = codec.encode(maximumAad, CREATED_AT);
        assertEquals(8 + 0xFFFF, maximum.length);
        assertEquals(0xFF, maximum[6] & 0xFF);
        assertEquals(0xFF, maximum[7] & 0xFF);

        IOException error = assertThrows(IOException.class,
                () -> codec.encode(maximumAad + "a", CREATED_AT));
        assertEquals("Header too large", error.getMessage());
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            boolean matches = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    matches = false;
                    break;
                }
            }
            if (matches) return true;
        }
        return false;
    }
}
