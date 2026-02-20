package io.github.em.verilog;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class EcdsaSigCodecTest {

    @Test
    void rawToDer_andBack_roundTrips() {
        SecureRandom rng = new SecureRandom();
        byte[] raw = new byte[64];
        rng.nextBytes(raw);

        byte[] der = EcdsaSigCodec.rawToDer(raw);
        byte[] back = EcdsaSigCodec.derToRaw(der);

        assertArrayEquals(raw, back);
    }

    @Test
    void should_prefix_high_bit_with_zero() {
        byte[] raw = new byte[64];
        Arrays.fill(raw, (byte) 0);
        // Set MSB of r and s, so DER INTEGER must be prefixed with 0x00 to remain positive.
        raw[0] = (byte) 0x80;
        raw[32] = (byte) 0x80;

        byte[] der = EcdsaSigCodec.rawToDer(raw);
        byte[] back = EcdsaSigCodec.derToRaw(der);
        assertArrayEquals(raw, back);
    }

    @Test
    void should_reject_wrong_length() {
        assertThrows(IllegalArgumentException.class, () -> EcdsaSigCodec.rawToDer(new byte[63]));
        assertThrows(IllegalArgumentException.class, () -> EcdsaSigCodec.rawToDer(new byte[65]));
    }
}
