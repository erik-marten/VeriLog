package io.github.em.verilog.io;

import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.crypto.XChaCha20Poly1305;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class EncryptedFrameCodecTest {

    private static final byte TYPE = (byte) 0x7f;
    private static final long SEQUENCE = 0x0102030405060708L;
    private static final String PREFIX = "caf\u00e9|v1";
    private static final byte[] PLAINTEXT = "{\"msg\":\"hi\"}".getBytes(StandardCharsets.UTF_8);
    // Captured from FramedLogFile before extraction with key 00..1f and nonce 00..17.
    private static final String PRE_REFACTOR_FRAME_HEX =
            "0000003d7f0102030405060708000102030405060708090a0b0c0d0e0f1011121314151617"
            + "e5e0620cf7f0b78c5b2d04b3091044c1a6930cfd8f78aea923cae38a";
    private static final String EXPECTED_AAD_HEX = "636166c3a97c7631000102030405060708007f";

    @Test
    void matches_pre_refactor_frame_and_aad() throws Exception {
        byte[] frame = new EncryptedFrameCodec(key(), PREFIX, fixedRandom(nonce()))
                .encode(TYPE, SEQUENCE, PLAINTEXT);
        assertArrayEquals(CryptoUtil.fromHex(PRE_REFACTOR_FRAME_HEX), frame);

        ByteBuffer bytes = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN);
        assertEquals(61, bytes.getInt());
        assertEquals(frame.length - 4, 61);
        assertEquals(TYPE, bytes.get());
        assertEquals(SEQUENCE, bytes.getLong());
        byte[] actualNonce = new byte[24];
        bytes.get(actualNonce);
        assertArrayEquals(nonce(), actualNonce);
        byte[] ct = new byte[bytes.remaining()];
        bytes.get(ct);
        assertArrayEquals(CryptoUtil.fromHex("e5e0620cf7f0b78c5b2d04b3091044c1a6930cfd8f78aea923cae38a"), ct);

        byte[] aad = CryptoUtil.fromHex(EXPECTED_AAD_HEX);
        assertArrayEquals(PLAINTEXT, XChaCha20Poly1305.decrypt(key(), actualNonce, ct, aad));
        byte[] changedType = aad.clone();
        changedType[changedType.length - 1] ^= 1;
        assertThrows(InvalidCipherTextException.class,
                () -> XChaCha20Poly1305.decrypt(key(), actualNonce, ct, changedType));
        byte[] wrongSeparator = aad.clone();
        wrongSeparator[PREFIX.getBytes(StandardCharsets.UTF_8).length] = 1;
        assertThrows(InvalidCipherTextException.class,
                () -> XChaCha20Poly1305.decrypt(key(), actualNonce, ct, wrongSeparator));
        byte[] changedSequence = aad.clone();
        changedSequence[PREFIX.getBytes(StandardCharsets.UTF_8).length + 1] ^= 1;
        assertThrows(InvalidCipherTextException.class,
                () -> XChaCha20Poly1305.decrypt(key(), actualNonce, ct, changedSequence));
        byte[] changedSecondSeparator = aad.clone();
        changedSecondSeparator[changedSecondSeparator.length - 2] = 1;
        assertThrows(InvalidCipherTextException.class,
                () -> XChaCha20Poly1305.decrypt(key(), actualNonce, ct, changedSecondSeparator));
    }

    @Test
    void retains_a_defensive_copy_of_the_dek() throws Exception {
        byte[] callerKey = key();
        EncryptedFrameCodec codec = new EncryptedFrameCodec(callerKey, PREFIX, fixedRandom(nonce()));
        Arrays.fill(callerKey, (byte) 0xff);

        assertArrayEquals(CryptoUtil.fromHex(PRE_REFACTOR_FRAME_HEX),
                codec.encode(TYPE, SEQUENCE, PLAINTEXT));
    }

    @Test
    void generates_a_new_nonce_for_each_frame() {
        CountingRandom rng = new CountingRandom();
        EncryptedFrameCodec codec = new EncryptedFrameCodec(key(), PREFIX, rng);

        byte[] first = codec.encode(TYPE, SEQUENCE, PLAINTEXT);
        byte[] second = codec.encode(TYPE, SEQUENCE + 1, PLAINTEXT);

        assertEquals(2, rng.calls);
        assertArrayEquals(nonce(), Arrays.copyOfRange(first, 13, 37));
        byte[] nextNonce = new byte[24];
        for (int i = 0; i < nextNonce.length; i++) nextNonce[i] = (byte) (i + 24);
        assertArrayEquals(nextNonce, Arrays.copyOfRange(second, 13, 37));
    }

    @Test
    void rejects_invalid_dek_lengths_like_framed_log_file() {
        for (byte[] invalid : new byte[][]{null, new byte[31], new byte[33]}) {
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> new EncryptedFrameCodec(invalid, PREFIX));
            assertEquals("DEK must be 32 bytes", error.getMessage());
        }
    }

    private static byte[] key() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) key[i] = (byte) i;
        return key;
    }

    private static byte[] nonce() {
        byte[] nonce = new byte[24];
        for (int i = 0; i < nonce.length; i++) nonce[i] = (byte) i;
        return nonce;
    }

    private static SecureRandom fixedRandom(byte[] nonce) {
        return new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                assertEquals(24, bytes.length);
                System.arraycopy(nonce, 0, bytes, 0, bytes.length);
            }
        };
    }

    private static final class CountingRandom extends SecureRandom {
        private int calls;

        @Override
        public void nextBytes(byte[] bytes) {
            assertEquals(24, bytes.length);
            for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (calls * 24 + i);
            calls++;
        }
    }
}
