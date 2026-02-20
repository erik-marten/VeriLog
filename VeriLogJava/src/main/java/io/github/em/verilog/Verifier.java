package io.github.em.verilog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Iterator;

public final class Verifier {
    private Verifier() {}

    public static final class VerifyReport {
        public final boolean ok;
        public final long seq;
        public final String reason;

        private VerifyReport(boolean ok, long seq, String reason) {
            this.ok = ok; this.seq = seq; this.reason = reason;
        }

        public static VerifyReport ok() { return new VerifyReport(true, -1, null); }
        public static VerifyReport fail(long seq, String reason) { return new VerifyReport(false, seq, reason); }
    }

    public static VerifyReport verifySingle(JsonNode signedEntry, PublicKey pub) throws Exception {
        long seq = signedEntry.get("seq").longValue();

        // payload = signedEntry without entryHash & sig
        ObjectNode payload = signedEntry.deepCopy();
        payload.remove("entryHash");
        payload.remove("sig");

        String canonicalPayload = CanonicalJson.canonicalize(payload);
        byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
        String computedHex = CryptoUtil.toHexLower(entryHashBytes);

        String expectedHex = signedEntry.get("entryHash").textValue();
        if (!computedHex.equals(expectedHex)) {
            return VerifyReport.fail(seq, "entryHash mismatch");
        }

        byte[] sigRaw = Base64.getDecoder().decode(signedEntry.get("sig").textValue());
        byte[] sigDer = EcdsaSigCodec.rawToDer(sigRaw);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(pub);
        verifier.update(entryHashBytes);
        boolean ok = verifier.verify(sigDer);

        return ok ? VerifyReport.ok() : VerifyReport.fail(seq, "signature invalid");
    }

    // optional helper: verify chain (seq contiguous + prevHash)
    public static VerifyReport verifyChain(Iterator<JsonNode> entries, PublicKey pub) throws Exception {
        String prevEntryHash = null;
        long expectedSeq = 1;

        while (entries.hasNext()) {
            JsonNode e = entries.next();
            long seq = e.get("seq").longValue();
            if (seq != expectedSeq) return VerifyReport.fail(seq, "seq not contiguous (expected " + expectedSeq + ")");

            VerifyReport rep = verifySingle(e, pub);
            if (!rep.ok) return rep;

            String prevHash = e.get("prevHash").textValue();
            if (seq == 1) {
                if (!prevHash.equals("0".repeat(64))) return VerifyReport.fail(seq, "prevHash must be zeros for seq=1");
            } else {
                if (!prevHash.equals(prevEntryHash)) return VerifyReport.fail(seq, "prevHash mismatch");
            }

            prevEntryHash = e.get("entryHash").textValue();
            expectedSeq++;
        }

        return VerifyReport.ok();
    }
}