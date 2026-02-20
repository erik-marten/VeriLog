package io.github.em.verilog.sign;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.em.verilog.CanonicalJson;
import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.audit.HashChainState;
import io.github.em.verilog.audit.SignedEntryFactory;
import io.github.em.verilog.reader.BcEcdsaVerifier;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SignedEntryFactoryTest {

    private static KeyPair genP256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    @Test
    void should_create_signed_entry_and_update_chain_when_entry_is_valid() throws Exception {
        KeyPair kp = genP256();
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        var signer = new BcEcdsaP256Signer(pkcs8, spki, true);
        ECPublicKeyParameters pub = BcPublicKeyLoader.fromSpkiDer(spki);

        HashChainState chain = HashChainState.fresh();
        SignedEntryFactory f = new SignedEntryFactory();
        ObjectMapper om = new ObjectMapper();

        Instant ts = Instant.parse("2026-02-20T20:00:00Z");

        byte[] json1 = f.buildSignedEntryJsonUtf8(
                chain, signer,
                "bob", "TEST_EVENT",
                Map.of("x", 1, "msg", "hello"),
                ts
        );

        JsonNode n1 = om.readTree(json1);
        assertEquals(1, n1.get("version").asInt());
        assertEquals(1L, n1.get("seq").asLong());
        assertEquals("bob", n1.get("actor").asText());
        assertEquals("TEST_EVENT", n1.get("eventType").asText());
        assertEquals(signer.keyId(), n1.get("keyId").asText());

        String prevHash1 = n1.get("prevHash").asText();
        assertEquals("0".repeat(64), prevHash1, "First entry should use genesis prevHash");

        String entryHashHex1 = n1.get("entryHash").asText();
        assertEquals(chain.prevHashHex(), entryHashHex1, "Chain prevHash should update to entryHash");

        byte[] sig1 = Base64.getDecoder().decode(n1.get("sig").asText());
        assertEquals(64, sig1.length);

        // Verify entryHash matches canonicalization of unsigned fields
        var unsigned1 = n1.deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) unsigned1).remove("entryHash");
        ((com.fasterxml.jackson.databind.node.ObjectNode) unsigned1).remove("sig");

        String canonical1 = CanonicalJson.canonicalize(unsigned1);
        byte[] computedHash1 = CryptoUtil.sha256Utf8(canonical1);
        assertEquals(entryHashHex1, CryptoUtil.toHexLower(computedHash1));

        assertTrue(BcEcdsaVerifier.verifyEntryHashSig(pub, computedHash1, sig1));

        // Second entry: prevHash should equal entryHash of first
        byte[] json2 = f.buildSignedEntryJsonUtf8(
                chain, signer,
                "bob", "TEST_EVENT_2",
                Map.of("y", true),
                ts.plusSeconds(1)
        );

        JsonNode n2 = om.readTree(json2);
        assertEquals(2L, n2.get("seq").asLong());
        assertEquals(entryHashHex1, n2.get("prevHash").asText(), "Second entry must link to first entryHash");
    }

    @Test
    void should_fail_signature_verification_when_payload_is_tampered() throws Exception {
        KeyPair kp = genP256();
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        var signer = new BcEcdsaP256Signer(pkcs8, spki, true);
        ECPublicKeyParameters pub = BcPublicKeyLoader.fromSpkiDer(spki);

        HashChainState chain = HashChainState.fresh();
        SignedEntryFactory f = new SignedEntryFactory();
        ObjectMapper om = new ObjectMapper();

        byte[] json = f.buildSignedEntryJsonUtf8(
                chain, signer,
                "bob", "TEST_EVENT",
                Map.of("x", 1),
                Instant.parse("2026-02-20T20:00:00Z")
        );

        // Tamper: change actor
        var node = (com.fasterxml.jackson.databind.node.ObjectNode) om.readTree(json);
        node.put("actor", "mallory");

        // Recompute hash from tampered unsigned and verify that signature no longer matches
        var unsigned = node.deepCopy();
        unsigned.remove("entryHash");
        unsigned.remove("sig");

        byte[] entryHash32 = CryptoUtil.sha256Utf8(CanonicalJson.canonicalize(unsigned));
        byte[] sig = Base64.getDecoder().decode(node.get("sig").asText());

        assertFalse(BcEcdsaVerifier.verifyEntryHashSig(pub, entryHash32, sig));
    }
}