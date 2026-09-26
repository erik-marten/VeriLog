package io.github.em.verilog.crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class XChaCha20Poly1305Test {

    @Test
    void should_encrypt_decrypt_round_trips_with_aad() throws Exception {
        SecureRandom rng = new SecureRandom();
        byte[] key = new byte[XChaCha20Poly1305.KEY_LEN];
        byte[] nonce = new byte[XChaCha20Poly1305.NONCE_LEN];
        rng.nextBytes(key);
        rng.nextBytes(nonce);

        byte[] pt = "hello verilog".getBytes();
        byte[] aad = "aad".getBytes();

        byte[] ct = XChaCha20Poly1305.encrypt(key, nonce, pt, aad);
        byte[] back = XChaCha20Poly1305.decrypt(key, nonce, ct, aad);
        assertArrayEquals(pt, back);
    }

    @Test
    void should_fail_decrypt_if_aad_differs() throws Exception {
        SecureRandom rng = new SecureRandom();
        byte[] key = new byte[XChaCha20Poly1305.KEY_LEN];
        byte[] nonce = new byte[XChaCha20Poly1305.NONCE_LEN];
        rng.nextBytes(key);
        rng.nextBytes(nonce);

        byte[] pt = "hello".getBytes();
        byte[] ct = XChaCha20Poly1305.encrypt(key, nonce, pt, "aad1".getBytes());

        assertThrows(InvalidCipherTextException.class,
                () -> XChaCha20Poly1305.decrypt(key, nonce, ct, "aad2".getBytes()));
    }

    @Test
    void should_rejext_bad_key_or_nonce_length_while_encryting() {
        assertThrows(IllegalArgumentException.class,
                () -> XChaCha20Poly1305.encrypt(new byte[31], new byte[24], new byte[0], null));
        assertThrows(IllegalArgumentException.class,
                () -> XChaCha20Poly1305.encrypt(new byte[32], new byte[23], new byte[0], null));
    }
}
