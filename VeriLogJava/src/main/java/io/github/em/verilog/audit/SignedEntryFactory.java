package io.github.em.verilog.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.em.verilog.CanonicalJson;
import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.sign.LogSigner;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

public final class SignedEntryFactory {

    private final ObjectMapper om = new ObjectMapper();

    public byte[] buildSignedEntryJsonUtf8(
            HashChainState chain,
            LogSigner signer,
            String actor,
            String eventType,
            Map<String, Object> event,
            Instant tsUtc
    ) throws Exception {

        long seq = chain.allocateSeq();

        ObjectNode unsigned = om.createObjectNode();
        unsigned.put("version", 1);
        unsigned.put("seq", seq);
        unsigned.put("ts", tsUtc.toString());
        unsigned.put("actor", actor);
        unsigned.put("eventType", eventType);
        unsigned.set("event", om.valueToTree(event));
        unsigned.put("prevHash", chain.prevHashHex());
        unsigned.put("keyId", signer.keyId());

        String canonicalPayload = CanonicalJson.canonicalize(unsigned);
        byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
        String entryHashHex = CryptoUtil.toHexLower(entryHashBytes);

        byte[] sigRaw = signer.signEntryHash(entryHashBytes);
        String sigB64 = Base64.getEncoder().encodeToString(sigRaw);

        ObjectNode signed = unsigned.deepCopy();
        signed.put("entryHash", entryHashHex);
        signed.put("sig", sigB64);

        chain.updatePrevHash(entryHashHex);

        return signed.toString().getBytes(StandardCharsets.UTF_8);
    }
}