package io.github.em.verilog;

import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.em.verilog.errors.VeriLogCryptoException;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.node.LongNode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class VerifierTest {

    private static final ObjectCodec OM = new ObjectMapper();

    @Test
    void should_reject_when_wrong_signature() throws Exception {
        String json = Files.readString(Path.of("src/test/resources/vectors_v1.json"));
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(json);

        PublicKey pub = PemKeys.importEcPublicKeyFromPem(root.get("publicKeyPem").textValue());

        JsonNode entryUnsigned = root.get("entryUnsigned");
        String canonicalActual = CanonicalJson.canonicalize(entryUnsigned);
        String hashActual = CryptoUtil.toHexLower(CryptoUtil.sha256Utf8(canonicalActual));

        ObjectNode signed = entryUnsigned.deepCopy();
        signed.put("entryHash", hashActual);
        String sigB64 = root.get("signatureBase64_rawRconcatS").textValue();

        // Flip 1 bit in the signature
        byte[] raw = java.util.Base64.getDecoder().decode(sigB64);
        raw[0] ^= 0x01;
        signed.put("sig", java.util.Base64.getEncoder().encodeToString(raw));

        var rep = Verifier.verifySingle(signed, pub);
        assertFalse(rep.valid);
    }

    @Test
    void should_throw_null_pointer_when_signedEntry_is_null() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        NullPointerException ex = assertThrows(
                NullPointerException.class,
                () -> Verifier.verifySingle(null, kp.getPublic())
        );

        assertEquals("signedEntry", ex.getMessage());
    }

    @Test
    void should_throw_null_pointer_when_pub_is_null() {
        ObjectNode entry = (ObjectNode) OM.createObjectNode();
        NullPointerException ex = assertThrows(
                NullPointerException.class,
                () -> Verifier.verifySingle(entry, null)
        );

        assertEquals("pub", ex.getMessage());
    }

    @Test
    void should_fail_when_required_fields_are_missing() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();
        ObjectNode entry = (ObjectNode) OM.createObjectNode(); // empty

        Verifier.VerifyReport rep = Verifier.verifySingle(entry, kp.getPublic());

        assertFalse(rep.valid);
        assertEquals(-1, rep.seq);
        assertEquals("missing required fields", rep.reason);
    }

    @Test
    void should_fail_when_signature_is_not_base64() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        ObjectNode entry = (ObjectNode) OM.createObjectNode();
        entry.put("seq", 1);
        entry.put("eventType", "evt");
        entry.set("event", ((ObjectNode) OM.createObjectNode()).put("x", 1));

        // Put a placeholder sig so it exists
        entry.put("sig", "placeholder");

        // Compute correct entryHash for the payload (entry without entryHash & sig)
        ObjectNode payload = entry.deepCopy();
        payload.remove("entryHash");
        payload.remove("sig");

        String canonicalPayload = CanonicalJson.canonicalize(payload);
        byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
        String entryHashHex = CryptoUtil.toHexLower(entryHashBytes);

        entry.put("entryHash", entryHashHex);

        // entryHash stays correct so we reach the sig decode
        entry.put("sig", "!!!not_base64!!!");

        Verifier.VerifyReport rep = Verifier.verifySingle(entry, kp.getPublic());

        assertFalse(rep.valid);
        assertEquals(1, rep.seq);
        assertEquals("signature encoding invalid", rep.reason);
    }

    @Test
    void should_fail_when_entry_hash_mismatches() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        ObjectNode entry = (ObjectNode) OM.createObjectNode();
        entry.put("seq", 1);
        entry.put("prevHash", "0".repeat(64));
        entry.put("eventType", "evt");
        entry.set("event", ((ObjectNode) OM.createObjectNode()).put("x", 1));
        entry.put("entryHash", "0".repeat(64));         // wrong on purpose
        entry.put("sig", java.util.Base64.getEncoder().encodeToString(new byte[64]));

        Verifier.VerifyReport rep = Verifier.verifySingle(entry, kp.getPublic());

        assertFalse(rep.valid);
        assertEquals(1, rep.seq);
        assertEquals("entryHash mismatch", rep.reason);
    }

    @Test
    void should_throw_null_pointer_when_entries_is_null() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        assertThrows(NullPointerException.class, () -> Verifier.verifyChain(null, kp.getPublic()));
    }

    @Test
    void should_throw_null_pointer_when_pub_is_null_in_verifyChain() {
        assertThrows(NullPointerException.class, () -> Verifier.verifyChain(java.util.List.<com.fasterxml.jackson.databind.JsonNode>of().iterator(), null));
    }

    @Test
    void should_fail_when_seq_not_contiguous_in_chain() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        ObjectNode e1 = (ObjectNode) OM.createObjectNode();
        e1.put("seq", 2); // should start at 1
        e1.put("prevHash", "0".repeat(64));
        e1.put("entryHash", "0".repeat(64));
        e1.put("sig", java.util.Base64.getEncoder().encodeToString(new byte[64]));

        Verifier.VerifyReport rep = Verifier.verifyChain(java.util.List.of(e1).iterator(), kp.getPublic());

        assertFalse(rep.valid);
        assertEquals(2, rep.seq);
        assertTrue(rep.reason.startsWith("seq not contiguous"));
    }

    @Test
    void should_throw_crypto_exception_when_public_key_is_incompatible() throws Exception {
        var rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        var kp = rsa.generateKeyPair(); // NOT EC

        ObjectNode entry = (ObjectNode) OM.createObjectNode();
        entry.put("seq", 1);
        entry.put("eventType", "evt");
        entry.set("event", ((ObjectNode) OM.createObjectNode()).put("x", 1));

        entry.put("sig", java.util.Base64.getEncoder().encodeToString(new byte[64]));

        // Compute correct entryHash for payload = entry without entryHash & sig
        ObjectNode payload = entry.deepCopy();
        payload.remove("entryHash");
        payload.remove("sig");

        String canonicalPayload = CanonicalJson.canonicalize(payload);
        byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
        String entryHashHex = CryptoUtil.toHexLower(entryHashBytes);

        entry.put("entryHash", entryHashHex);

        VeriLogCryptoException ex = assertThrows(
                VeriLogCryptoException.class,
                () -> Verifier.verifySingle(entry, kp.getPublic())
        );

        assertEquals("crypto.signature_verify_failed", ex.getMessageKey());
    }

    @Test
    void should_fail_when_signature_raw_format_is_invalid() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        ObjectNode entry = (ObjectNode) OM.createObjectNode();
        entry.put("seq", 1);
        entry.put("eventType", "evt");
        entry.set("event", ((ObjectNode) OM.createObjectNode()).put("x", 1));

        // compute correct entryHash for the payload (entry without entryHash & sig)
        ObjectNode payload = entry.deepCopy();
        payload.remove("entryHash");
        payload.remove("sig");

        String canonicalPayload = CanonicalJson.canonicalize(payload);
        byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
        String entryHashHex = CryptoUtil.toHexLower(entryHashBytes);
        entry.put("entryHash", entryHashHex);

        // valid base64, but invalid raw ECDSA signature length/shape (not 64 bytes r||s)
        entry.put("sig", java.util.Base64.getEncoder().encodeToString(new byte[10]));

        Verifier.VerifyReport rep = Verifier.verifySingle(entry, kp.getPublic());

        assertFalse(rep.valid);
        assertEquals(1, rep.seq);
        assertEquals("signature encoding invalid", rep.reason);
    }

    @Test
    void should_fail_chain_when_entry_missing_seq_or_prevHash() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        ObjectNode e1 = (ObjectNode) OM.createObjectNode();
        e1.put("seq", 1);
        // no prevHash

        Verifier.VerifyReport rep = Verifier.verifyChain(java.util.List.of(e1).iterator(), kp.getPublic());

        assertFalse(rep.valid);
        assertEquals(-1, rep.seq);
        assertEquals("missing required fields", rep.reason);
    }

    @Test
    void should_fail_chain_when_seq1_prevHash_is_not_zeros() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        ObjectNode e1 = makeSignedEntry(1, "1".repeat(64), kp.getPrivate()); // wrong for seq=1

        Verifier.VerifyReport rep = Verifier.verifyChain(java.util.List.of(e1).iterator(), kp.getPublic());

        assertFalse(rep.valid);
        assertEquals(1, rep.seq);
        assertEquals("prevHash must be zeros for seq=1", rep.reason);
    }

    @Test
    void should_fail_chain_when_prevHash_mismatches_previous_entryHash() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        ObjectNode e1 = makeSignedEntry(1, "0".repeat(64), kp.getPrivate());
        ObjectNode e2 = makeSignedEntry(2, "9".repeat(64), kp.getPrivate()); // should equal e1.entryHash

        Verifier.VerifyReport rep = Verifier.verifyChain(java.util.List.of(e1, e2).iterator(), kp.getPublic());

        assertFalse(rep.valid);
        assertEquals(2, rep.seq);
        assertEquals("prevHash mismatch", rep.reason);
    }

    @Test
    void should_wrap_runtime_exception_as_verifier_unexpected_error() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        com.fasterxml.jackson.databind.JsonNode node = org.mockito.Mockito.mock(com.fasterxml.jackson.databind.JsonNode.class);
        org.mockito.Mockito.when(node.hasNonNull("seq")).thenReturn(true);
        org.mockito.Mockito.when(node.hasNonNull("entryHash")).thenReturn(true);
        org.mockito.Mockito.when(node.hasNonNull("sig")).thenReturn(true);
        org.mockito.Mockito.when(node.get("seq")).thenReturn(LongNode.valueOf(1L));
        org.mockito.Mockito.when(node.deepCopy()).thenThrow(new RuntimeException("boom"));

        VeriLogCryptoException ex = assertThrows(
                VeriLogCryptoException.class,
                () -> Verifier.verifySingle(node, kp.getPublic())
        );

        assertEquals("crypto.verifier_unexpected_error", ex.getMessageKey());
        assertNotNull(ex.getCause());
        assertEquals("boom", ex.getCause().getMessage());
    }

    @Test
    void should_return_success_when_chain_is_valid() throws Exception {
        var kp = KeyPairGenerator.getInstance("EC").generateKeyPair();

        ObjectNode e1 = makeSignedEntry(1, "0".repeat(64), kp.getPrivate());
        ObjectNode e2 = makeSignedEntry(2, e1.get("entryHash").textValue(), kp.getPrivate());

        var rep = Verifier.verifyChain(java.util.List.of(e1, e2).iterator(), kp.getPublic());

        assertTrue(rep.valid);
        assertEquals(-1, rep.seq);
        assertNull(rep.reason);
    }

    // Helpers

    /**
     * Minimal DER->(r||s) converter for ECDSA signatures:
     * DER is usually: 0x30 len 0x02 lenR R 0x02 lenS S
     */
    private static byte[] derToRawRsFixed64(byte[] der) {
        int i = 0;
        if ((der[i++] & 0xFF) != 0x30) throw new IllegalArgumentException("Not a SEQUENCE");
        int seqLen = der[i++] & 0xFF;
        if (seqLen > 0x80) { // long-form length
            int n = seqLen & 0x7F;
            seqLen = 0;
            for (int k = 0; k < n; k++) seqLen = (seqLen << 8) | (der[i++] & 0xFF);
        }

        if ((der[i++] & 0xFF) != 0x02) throw new IllegalArgumentException("Expected INTEGER r");
        int rLen = der[i++] & 0xFF;
        byte[] r = java.util.Arrays.copyOfRange(der, i, i + rLen);
        i += rLen;

        if ((der[i++] & 0xFF) != 0x02) throw new IllegalArgumentException("Expected INTEGER s");
        int sLen = der[i++] & 0xFF;
        byte[] s = java.util.Arrays.copyOfRange(der, i, i + sLen);

        // Left-pad / truncate to 32 bytes each
        byte[] r32 = new byte[32];
        byte[] s32 = new byte[32];
        copyBigIntToFixed(r, r32);
        copyBigIntToFixed(s, s32);

        byte[] out = new byte[64];
        System.arraycopy(r32, 0, out, 0, 32);
        System.arraycopy(s32, 0, out, 32, 32);
        return out;
    }

    private static void copyBigIntToFixed(byte[] src, byte[] dst32) {
        // DER INTEGER may have leading 0x00 to force positive- strip leading zeros
        int start = 0;
        while (start < src.length - 1 && src[start] == 0x00) start++;
        int len = src.length - start;
        if (len > 32) {
            start = src.length - 32;
            len = 32;
        }
        System.arraycopy(src, start, dst32, 32 - len, len);
    }

    private static ObjectNode makeSignedEntry(long seq, String prevHash, java.security.PrivateKey priv) throws Exception {
        ObjectNode entry = (ObjectNode) OM.createObjectNode();
        entry.put("seq", seq);
        entry.put("prevHash", prevHash);
        entry.put("eventType", "evt");
        entry.set("event", ((ObjectNode) OM.createObjectNode()).put("x", (int) seq));

        // payload used for entryHash: entry without entryHash & sig
        ObjectNode payload = entry.deepCopy();
        payload.remove("entryHash");
        payload.remove("sig");

        String canonicalPayload = CanonicalJson.canonicalize(payload);
        byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
        String entryHashHex = CryptoUtil.toHexLower(entryHashBytes);
        entry.put("entryHash", entryHashHex);

        // Sign the entryHashBytes (Verifier does verifier.update(entryHashBytes))
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(priv);
        s.update(entryHashBytes);
        byte[] der = s.sign();

        // Convert DER -> raw r||s (64 bytes), because Verifier expects raw and converts raw->DER
        byte[] raw = derToRawRsFixed64(der);

        entry.put("sig", Base64.getEncoder().encodeToString(raw));
        return entry;
    }
}
