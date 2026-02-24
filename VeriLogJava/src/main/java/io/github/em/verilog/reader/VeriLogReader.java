/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.reader;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.em.verilog.CanonicalJson;
import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.crypto.XChaCha20Poly1305;
import io.github.em.verilog.errors.VeriLogCryptoException;
import io.github.em.verilog.errors.VeriLogException;
import io.github.em.verilog.errors.VeriLogIoException;
import io.github.em.verilog.errors.VeriLogJsonException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

public final class VeriLogReader {

    private final ObjectMapper om = new ObjectMapper();
    private static final String ENTRY_HASH = "entryHash";
    private static final String CURRENT_VLOG = "current.vlog";
    public VerifyReport verifyFile(Path vlogPath, byte[] dek32, PublicKeyResolver keyResolver)
            throws VeriLogException {
        return verifyFile(vlogPath, dek32, keyResolver, false);
    }

    public VerifyReport verifyFile(Path vlogPath, byte[] dek32, PublicKeyResolver keyResolver, boolean tolerateTrailingPartialFrame)
            throws VeriLogException {

        if (vlogPath == null) throw new NullPointerException("vlogPath");
        if (dek32 == null) throw new NullPointerException("dek32");
        if (keyResolver == null) throw new NullPointerException("keyResolver");

        long expectedSeq = 1;
        String prevHashExpected = "0".repeat(64);
        long lastOk = 0;

        try (FramedFileReader r = new FramedFileReader(vlogPath)) {

            // Header JSON: if the header is not parsable, cannot verify => JSON exception
            final JsonNode header;
            try {
                String headerJson = new String(r.rawHeaderJsonBytes(), StandardCharsets.UTF_8);
                header = om.readTree(headerJson);
            } catch (JsonProcessingException e) {
                throw new VeriLogJsonException("json.invalid_header", e);
            }

            String aadPrefix = header.has("aad") ? header.get("aad").asText() : "VeriLog|v1";
            byte[] aadPrefixBytes = aadPrefix.getBytes(StandardCharsets.UTF_8);

            r.positionAtFirstFrame();

            while (true) {
                Frame f = r.readNextFrame(tolerateTrailingPartialFrame);
                if (f == null) break;

                if (f.seq != expectedSeq) {
                    return VerifyReport.fail(f.seq, "frame seq not contiguous (expected " + expectedSeq + ")");
                }
                if (f.type != 1) {
                    return VerifyReport.fail(f.seq, "unsupported frame type: " + f.type);
                }

                byte[] aad = buildAad(aadPrefixBytes, f.type, f.seq);

                final byte[] plaintext;
                try {
                    plaintext = XChaCha20Poly1305.decrypt(dek32, f.nonce24, f.ct, aad);
                } catch (InvalidCipherTextException e) {
                    // expected verification failure
                    return VerifyReport.fail(f.seq, "decrypt/auth failed");
                }

                final JsonNode signed;
                try {
                    signed = om.readTree(new String(plaintext, StandardCharsets.UTF_8));
                } catch (JsonProcessingException e) {
                    // decrypted but not JSON: treated as verification failure (content invalid)
                    return VerifyReport.fail(f.seq, "invalid signed JSON");
                }

                // Basic required fields presence (avoid NPE)
                if (!signed.hasNonNull("seq")
                        || !signed.hasNonNull("prevHash")
                        || !signed.hasNonNull(ENTRY_HASH)
                        || !signed.hasNonNull("keyId")
                        || !signed.hasNonNull("sig")) {
                    return VerifyReport.fail(f.seq, "missing required fields in signed entry");
                }

                long jsonSeq = signed.get("seq").asLong();
                if (jsonSeq != f.seq) {
                    return VerifyReport.fail(f.seq, "json seq mismatch (json=" + jsonSeq + ")");
                }

                String prevHash = signed.get("prevHash").asText();
                if (!prevHash.equals(prevHashExpected)) {
                    return VerifyReport.fail(f.seq, "prevHash mismatch");
                }

                final String canonicalPayload;
                try {
                    canonicalPayload = canonicalizeWithout(signed);
                } catch (VeriLogJsonException e) {
                    // canonicalization failure is unexpected (library/JSON issue)
                    throw e;
                }

                byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
                String computedEntryHashHex = CryptoUtil.toHexLower(entryHashBytes);

                String expectedEntryHashHex = signed.get(ENTRY_HASH).asText();
                if (!computedEntryHashHex.equals(expectedEntryHashHex)) {
                    return VerifyReport.fail(f.seq, "entryHash mismatch");
                }

                String keyId = signed.get("keyId").asText();
                ECPublicKeyParameters pub = keyResolver.resolveByKeyIdHex(keyId);
                if (pub == null) {
                    return VerifyReport.fail(f.seq, "unknown keyId: " + keyId);
                }

                final byte[] sigRaw;
                try {
                    sigRaw = Base64.getDecoder().decode(signed.get("sig").asText());
                } catch (IllegalArgumentException e) {
                    return VerifyReport.fail(f.seq, "signature encoding invalid");
                }

                final boolean sigOk;
                try {
                    sigOk = BcEcdsaVerifier.verifyEntryHashSig(pub, entryHashBytes, sigRaw);
                } catch (VeriLogCryptoException e) {
                    // unexpected crypto failure
                    throw e;
                }

                if (!sigOk) {
                    return VerifyReport.fail(f.seq, "signature invalid");
                }

                prevHashExpected = expectedEntryHashHex;
                expectedSeq++;
                lastOk = f.seq;
            }

        } catch (java.io.IOException e) {
            throw new VeriLogIoException("io.read_failed", e, vlogPath.toString());
        }

        return VerifyReport.success(lastOk);
    }

    public DirectoryVerifyReport verifyDirectory(Path logDir, byte[] dek32, PublicKeyResolver keyResolver)
            throws VeriLogException {
        return verifyDirectory(logDir, dek32, keyResolver, true);
    }

    /**
     * @param stopOnFirstFailure if true: stop at first failed file
     */
    public DirectoryVerifyReport verifyDirectory(Path logDir, byte[] dek32, PublicKeyResolver keyResolver, boolean stopOnFirstFailure)
            throws VeriLogException {

        if (logDir == null) throw new NullPointerException("logDir");
        if (dek32 == null) throw new NullPointerException("dek32");
        if (keyResolver == null) throw new NullPointerException("keyResolver");

        var report = new DirectoryVerifyReport();

        // list *.vlog, skip directories
        java.util.List<java.nio.file.Path> files = new java.util.ArrayList<>();
        try (var stream = java.nio.file.Files.list(logDir)) {
            stream
                    .filter(p -> java.nio.file.Files.isRegularFile(p))
                    .filter(p -> p.getFileName().toString().endsWith(".vlog"))
                    .forEach(files::add);
        } catch (java.io.IOException e) {
            throw new VeriLogIoException("io.read_failed", e, logDir.toString());
        }

        // Sort: name first, then lastModified
        files.sort((a, b) -> {
            int c = a.getFileName().toString().compareTo(b.getFileName().toString());
            if (c != 0) return c;
            try {
                long ta = java.nio.file.Files.getLastModifiedTime(a).toMillis();
                long tb = java.nio.file.Files.getLastModifiedTime(b).toMillis();
                return Long.compare(ta, tb);
            } catch (java.io.IOException ignored) {
                return 0;
            }
        });

        // current.vlog last
        files.sort((a, b) -> {
            String an = a.getFileName().toString();
            String bn = b.getFileName().toString();
            boolean ac = an.equals(CURRENT_VLOG);
            boolean bc = bn.equals(CURRENT_VLOG);
            if (ac == bc) return 0;
            return ac ? 1 : -1;
        });

        for (var f : files) {
            boolean tolerate = f.getFileName().toString().equals(CURRENT_VLOG);
            VerifyReport r = verifyFile(f, dek32, keyResolver, tolerate);

            report.add(new DirectoryVerifyReport.FileResult(f, r.valid, r.seq, r.reason));

            if (!r.valid && stopOnFirstFailure) break;
        }

        return report;
    }

    private byte[] buildAad(byte[] prefix, byte type, long seq) {
        // aad = prefix || 0x00 || uint64_be(seq) || 0x00 || type
        java.nio.ByteBuffer bb = java.nio.ByteBuffer
                .allocate(prefix.length + 1 + 8 + 1 + 1)
                .order(java.nio.ByteOrder.BIG_ENDIAN);

        bb.put(prefix);
        bb.put((byte) 0x00);
        bb.putLong(seq);
        bb.put((byte) 0x00);
        bb.put(type);
        return bb.array();
    }

    private String canonicalizeWithout(JsonNode obj) throws VeriLogJsonException {
        // Create a mutable copy as ObjectNode, remove fields, then canonicalize via CanonicalJson
        try {
            var copy = obj.deepCopy();
            if (copy.isObject()) {
                for (String r : new String[]{ENTRY_HASH, "sig"}) {
                    ((com.fasterxml.jackson.databind.node.ObjectNode) copy).remove(r);
                }
            }
            return CanonicalJson.canonicalize(copy);
        } catch (RuntimeException e) {
            throw new VeriLogJsonException("json.canonicalize_failed", e);
        } catch (VeriLogCryptoException e) {
            throw new RuntimeException(e);
        }
    }
}