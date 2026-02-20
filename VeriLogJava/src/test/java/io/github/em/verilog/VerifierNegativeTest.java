package io.github.em.verilog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

public class VerifierNegativeTest {

    @Test
    void verifySingle_rejectsWrongSignature() throws Exception {
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
}
