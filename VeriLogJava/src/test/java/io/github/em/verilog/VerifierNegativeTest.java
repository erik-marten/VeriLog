package io.github.em.verilog;

import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.em.verilog.errors.VeriLogCryptoException;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

public class VerifierNegativeTest {

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
        assertFalse(rep.ok);
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
    void should_throw_null_pointer_when_pub_is_null(){
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

        assertFalse(rep.ok);
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

        assertFalse(rep.ok);
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

        assertFalse(rep.ok);
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

        assertFalse(rep.ok);
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

        // Put any valid base64 sig  to reach initVerify
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
}
