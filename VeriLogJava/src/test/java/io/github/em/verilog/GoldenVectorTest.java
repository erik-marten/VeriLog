package io.github.em.verilog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

public class GoldenVectorTest {

    @Test
    public void should_verify_vectors() throws Exception {
        String json = Files.readString(Path.of("src/test/resources/vectors_v1.json"));
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(json);

        PublicKey pub = PemKeys.importEcPublicKeyFromPem(root.get("publicKeyPem").textValue());

        JsonNode entryUnsigned = root.get("entryUnsigned");
        String canonicalExpected = root.get("canonicalPayloadJson").textValue();
        String canonicalActual = CanonicalJson.canonicalize(entryUnsigned);
        assertEquals(canonicalExpected, canonicalActual);

        String hashExpected = root.get("entryHashHex").textValue();
        String hashActual = CryptoUtil.toHexLower(CryptoUtil.sha256Utf8(canonicalActual));
        assertEquals(hashExpected, hashActual);

        ObjectNode signed = entryUnsigned.deepCopy();
        signed.put("entryHash", hashExpected);
        signed.put("sig", root.get("signatureBase64_rawRconcatS").textValue());

        var rep = Verifier.verifySingle(signed, pub);
        assertTrue(rep.valid, rep.reason);
    }
}