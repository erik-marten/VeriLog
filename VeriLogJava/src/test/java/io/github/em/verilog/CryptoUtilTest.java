package io.github.em.verilog;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoUtilTest {

    @Test
    void hex_roundTrips_andAcceptsUppercase() {
        byte[] in = new byte[]{0x00, 0x01, 0x0f, 0x10, (byte) 0xab, (byte) 0xff};
        String hex = CryptoUtil.toHexLower(in);
        assertEquals("00010f10abff", hex);
        assertArrayEquals(in, CryptoUtil.fromHex(hex));
        assertArrayEquals(in, CryptoUtil.fromHex(hex.toUpperCase()));
    }

    @Test
    void should_reject_odd_length() {
        assertThrows(IllegalArgumentException.class, () -> CryptoUtil.fromHex("abc"));
    }

    @Test
    void should_reject_invalid_characters() {
        assertThrows(IllegalArgumentException.class, () -> CryptoUtil.fromHex("zz"));
    }
}
