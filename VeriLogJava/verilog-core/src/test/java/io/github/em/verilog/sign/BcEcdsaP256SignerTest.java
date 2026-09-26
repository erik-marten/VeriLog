package io.github.em.verilog.sign;

import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.reader.BcEcdsaVerifier;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class BcEcdsaP256SignerTest {

    private static KeyPair genP256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    @Test
    void should_compute_key_id_as_sha256_of_spki_der() throws Exception {
        KeyPair kp = genP256();
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        BcEcdsaP256Signer s = new BcEcdsaP256Signer(pkcs8, spki, true);

        String expected = CryptoUtil.toHexLower(CryptoUtil.sha256(spki));
        assertEquals(expected, s.keyId());
    }

    @Test
    void should_sign_and_verify_entry_hash_successfully() throws Exception {
        KeyPair kp = genP256();
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        BcEcdsaP256Signer signer = new BcEcdsaP256Signer(pkcs8, spki, true);

        byte[] entryHash32 = new byte[32];
        new SecureRandom().nextBytes(entryHash32);

        byte[] sig = signer.signEntryHash(entryHash32);
        assertEquals(64, sig.length);

        ECPublicKeyParameters pub = BcPublicKeyLoader.fromSpkiDer(spki);
        assertTrue(BcEcdsaVerifier.verifyEntryHashSig(pub, entryHash32, sig));
    }

    @Test
    void should_create_deterministic_signatures_when_signing_same_input() throws Exception {
        KeyPair kp = genP256();
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        BcEcdsaP256Signer signer = new BcEcdsaP256Signer(pkcs8, spki, true);

        byte[] entryHash32 = new byte[32];
        Arrays.fill(entryHash32, (byte) 7);

        byte[] sig1 = signer.signEntryHash(entryHash32);
        byte[] sig2 = signer.signEntryHash(entryHash32);

        assertArrayEquals(sig1, sig2, "RFC6979 should make signatures deterministic for same message/key");
    }

    @Test
    void should_enforce_low_s_normalization_when_enabled() throws Exception {
        KeyPair kp = genP256();
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        BcEcdsaP256Signer signer = new BcEcdsaP256Signer(pkcs8, spki, true);
        ECPublicKeyParameters pub = BcPublicKeyLoader.fromSpkiDer(spki);

        byte[] entryHash32 = new byte[32];
        new SecureRandom().nextBytes(entryHash32);

        byte[] sigRaw = signer.signEntryHash(entryHash32);

        // Decode r,s so we can check s <= n/2
        byte[] der = io.github.em.verilog.EcdsaSigCodec.rawToDer(sigRaw);
        var rs = StandardDSAEncoding.INSTANCE.decode(pub.getParameters().getN(), der);

        var n = pub.getParameters().getN();
        var halfN = n.shiftRight(1);

        assertTrue(rs[1].compareTo(halfN) <= 0, "Expected low-S normalization");
    }

    @Test
    void should_throw_exception_when_entry_hash_length_is_invalid() throws Exception {
        KeyPair kp = genP256();
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        BcEcdsaP256Signer signer = new BcEcdsaP256Signer(pkcs8, spki, true);

        assertThrows(IllegalArgumentException.class, () -> signer.signEntryHash(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> signer.signEntryHash(new byte[33]));
        assertThrows(IllegalArgumentException.class, () -> signer.signEntryHash(null));
    }
}