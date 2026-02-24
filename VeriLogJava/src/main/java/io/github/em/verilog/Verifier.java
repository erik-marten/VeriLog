/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.em.verilog.errors.VeriLogCryptoException;
import io.github.em.verilog.errors.VeriLogFormatException;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Iterator;
import java.util.Objects;

public final class Verifier {
    private Verifier() {
    }
    private static final String ENTRY_HASH = "entryHash";
    public static final class VerifyReport {
        public final boolean valid;
        public final long seq;
        public final String reason;

        private VerifyReport(boolean valid, long seq, String reason) {
            this.valid = valid;
            this.seq = seq;
            this.reason = reason;
        }

        public static VerifyReport success() {
            return new VerifyReport(true, -1, null);
        }

        public static VerifyReport fail(long seq, String reason) {
            return new VerifyReport(false, seq, reason);
        }
    }

    public static VerifyReport verifySingle(JsonNode signedEntry, PublicKey pub)
            throws VeriLogCryptoException {

        Objects.requireNonNull(signedEntry, "signedEntry");
        Objects.requireNonNull(pub, "pub");

        // Required fields check (avoid NPE)
        if (!signedEntry.hasNonNull("seq")
                || !signedEntry.hasNonNull(ENTRY_HASH)
                || !signedEntry.hasNonNull("sig")) {
            return VerifyReport.fail(-1, "missing required fields");
        }

        long seq = signedEntry.get("seq").longValue();

        try {
            ObjectNode payload = signedEntry.deepCopy();
            payload.remove(ENTRY_HASH);
            payload.remove("sig");

            String canonicalPayload = CanonicalJson.canonicalize(payload);
            byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
            String computedHex = CryptoUtil.toHexLower(entryHashBytes);

            String expectedHex = signedEntry.get(ENTRY_HASH).textValue();
            if (!computedHex.equals(expectedHex)) {
                return VerifyReport.fail(seq, "entryHash mismatch");
            }

            final byte[] sigRaw;
            try {
                sigRaw = Base64.getDecoder().decode(signedEntry.get("sig").textValue());
            } catch (IllegalArgumentException e) {
                return VerifyReport.fail(seq, "signature encoding invalid");
            }

            final byte[] sigDer;
            try {
                sigDer = EcdsaSigCodec.rawToDer(sigRaw);
            } catch (VeriLogFormatException e) {
                return VerifyReport.fail(seq, "signature encoding invalid");
            }

            Signature verifier;
            try {
                verifier = Signature.getInstance("SHA256withECDSA");
            } catch (Exception e) {
                throw new VeriLogCryptoException("crypto.signature_engine_unavailable", e);
            }

            try {
                verifier.initVerify(pub);
                verifier.update(entryHashBytes);
                boolean ok = verifier.verify(sigDer);
                return ok ? VerifyReport.success() : VerifyReport.fail(seq, "signature invalid");
            } catch (Exception e) {
                throw new VeriLogCryptoException("crypto.signature_verify_failed", e);
            }
        } catch (RuntimeException e) {
            // Unexpected programming/runtime issue
            throw new VeriLogCryptoException("crypto.verifier_unexpected_error", e);
        }
    }

    // optional helper: verify chain (seq contiguous + prevHash)
    public static VerifyReport verifyChain(Iterator<? extends JsonNode> entries, PublicKey pub)
            throws VeriLogCryptoException {

        Objects.requireNonNull(entries, "entries");
        Objects.requireNonNull(pub, "pub");
        String prevEntryHash = null;
        long expectedSeq = 1;

        while (entries.hasNext()) {
            JsonNode e = entries.next();

            if (!e.hasNonNull("seq") || !e.hasNonNull("prevHash")) {
                return VerifyReport.fail(-1, "missing required fields");
            }

            long seq = e.get("seq").longValue();
            if (seq != expectedSeq) {
                return VerifyReport.fail(seq,
                        "seq not contiguous (expected " + expectedSeq + ")");
            }

            VerifyReport rep = verifySingle(e, pub);
            if (!rep.valid) return rep;

            String prevHash = e.get("prevHash").textValue();

            if (seq == 1) {
                if (!prevHash.equals("0".repeat(64))) {
                    return VerifyReport.fail(seq,
                            "prevHash must be zeros for seq=1");
                }
            } else {
                if (!prevHash.equals(prevEntryHash)) {
                    return VerifyReport.fail(seq, "prevHash mismatch");
                }
            }

            prevEntryHash = e.get(ENTRY_HASH).textValue();
            expectedSeq++;
        }
        return VerifyReport.success();
    }
}