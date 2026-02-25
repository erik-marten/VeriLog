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
import io.github.em.verilog.errors.*;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Function;

import static java.nio.file.Files.getLastModifiedTime;

public final class VeriLogReader {

    private final ObjectMapper om = new ObjectMapper();
    private static final String ENTRY_HASH = "entryHash";
    private static final String CURRENT_VLOG = "current.vlog";
    private static Path path = null;

    public VerifyReport verifyFile(Path vlogPath, byte[] dek32, PublicKeyResolver keyResolver)
            throws VeriLogException {
        return verifyFile(vlogPath, dek32, keyResolver, false);
    }

    public VerifyReport verifyFile(
            Path vlogPath,
            byte[] dek32,
            PublicKeyResolver keyResolver,
            boolean tolerateTrailingPartialFrame
    ) throws VeriLogException {

        Objects.requireNonNull(vlogPath, "vlogPath");
        Objects.requireNonNull(dek32, "dek32");
        Objects.requireNonNull(keyResolver, "keyResolver");
        path = vlogPath;
        final State s = new State();

        try (FramedFileReader r = new FramedFileReader(vlogPath)) {
            final Header h = readHeader(r);

            r.positionAtFirstFrame();

            for (Frame f : r.frames(tolerateTrailingPartialFrame)) {
                VerifyReport failure = verifyOneFrame(f, s, h, dek32, keyResolver);
                if (failure != null) return failure;
            }

        } catch (java.io.IOException e) {
            throw new VeriLogIoException("io.read_failed", e, vlogPath.toString());
        }

        return VerifyReport.success(s.lastOk);
    }

    // ---------------------------
    // Pipeline
    // ---------------------------

    private VerifyReport verifyOneFrame(
            Frame f,
            State s,
            Header h,
            byte[] dek32,
            PublicKeyResolver keyResolver
    ) throws VeriLogException {

        VerifyReport r;

        if ((r = verifyFrameMeta(f, s.expectedSeq)) != null) return r;

        final byte[] aad = buildAad(h.aadPrefixBytes, f.type, f.seq);

        final byte[] plaintext;
        try {
            plaintext = XChaCha20Poly1305.decrypt(dek32, f.nonce24, f.ct, aad);
        } catch (InvalidCipherTextException e) {
            return VerifyReport.fail(f.seq, "decrypt/auth failed");
        }

        final JsonNode signed;
        try {
            signed = om.readTree(new String(plaintext, StandardCharsets.UTF_8));
        } catch (JsonProcessingException e) {
            return VerifyReport.fail(f.seq, "invalid signed JSON");
        }

        if ((r = verifyRequiredFields(signed, f)) != null) return r;
        if ((r = verifyJsonSeqMatchesFrame(signed, f)) != null) return r;
        if ((r = verifyPrevHashMatches(signed, f, s.prevHashExpected)) != null) return r;

        final CanonicalAndHash ch = canonicalizeAndHash(signed, f);
        if (ch.failure != null) return ch.failure;

        final ECPublicKeyParameters pub = resolveKeyOrFail(signed, keyResolver, f);
        if (pub == null) return VerifyReport.fail(f.seq, "unknown keyId"); // should not happen

        final byte[] sigRaw = decodeSignatureOrFail(signed, f);
        if (sigRaw == null) return VerifyReport.fail(f.seq, "signature encoding invalid");

        final boolean sigOk;
        try {
            sigOk = BcEcdsaVerifier.verifyEntryHashSig(pub, ch.entryHashBytes, sigRaw);
        } catch (VeriLogCryptoException e) {
            // unexpected crypto failure (engine/provider/etc)
            throw e;
        }

        if (!sigOk) {
            return VerifyReport.fail(f.seq, "signature invalid");
        }

        // Update state (single place, after full success)
        s.prevHashExpected = ch.expectedEntryHashHex;
        s.expectedSeq++;
        s.lastOk = f.seq;

        return null;
    }

    // ---------------------------
    // Header
    // ---------------------------

    private Header readHeader(FramedFileReader r) throws VeriLogException {
        final byte[] raw = r.rawHeaderJsonBytes();
        if (raw == null || raw.length == 0) {
            throw new VeriLogFormatException("format.missing_header", path.toString());
        }
        final JsonNode header;
        try {
            String headerJson = new String(r.rawHeaderJsonBytes(), StandardCharsets.UTF_8);
            header = om.readTree(headerJson);
        } catch (JsonProcessingException e) {
            throw new VeriLogJsonException("json.invalid_header", e);
        }

        String aadPrefix = header.has("aad") ? header.get("aad").asText() : "VeriLog|v1";
        return new Header(aadPrefix.getBytes(StandardCharsets.UTF_8));
    }

    private static final class Header {
        final byte[] aadPrefixBytes;

        Header(byte[] aadPrefixBytes) {
            this.aadPrefixBytes = aadPrefixBytes;
        }
    }

    private static final class State {
        long expectedSeq = 1;
        String prevHashExpected = "0".repeat(64);
        long lastOk = 0;
    }

    // ----------------------------------------------
    // Checks (fail -> VerifyReport, success -> null)
    // ---------------------------------------------

    private VerifyReport verifyFrameMeta(Frame f, long expectedSeq) {
        Objects.requireNonNull(f, "frame");

        if (f.seq != expectedSeq) {
            return VerifyReport.fail(f.seq, "frame seq not contiguous (expected " + expectedSeq + ")");
        }
        if (f.type != 1) {
            return VerifyReport.fail(f.seq, "unsupported frame type: " + f.type);
        }
        return null;
    }

    private VerifyReport verifyRequiredFields(JsonNode signed, Frame f) {
        if (!signed.hasNonNull("seq")
                || !signed.hasNonNull("prevHash")
                || !signed.hasNonNull(ENTRY_HASH)
                || !signed.hasNonNull("keyId")
                || !signed.hasNonNull("sig")) {
            return VerifyReport.fail(f.seq, "missing required fields in signed entry");
        }
        return null;
    }

    private VerifyReport verifyJsonSeqMatchesFrame(JsonNode signed, Frame f) {
        long jsonSeq = signed.get("seq").asLong();
        if (jsonSeq != f.seq) {
            return VerifyReport.fail(f.seq, "json seq mismatch (json=" + jsonSeq + ")");
        }
        return null;
    }

    private VerifyReport verifyPrevHashMatches(JsonNode signed, Frame f, String prevHashExpected) {
        String prevHash = signed.get("prevHash").asText();
        if (!prevHash.equals(prevHashExpected)) {
            return VerifyReport.fail(f.seq, "prevHash mismatch");
        }
        return null;
    }

    private static final class CanonicalAndHash {
        final byte[] entryHashBytes;
        final String expectedEntryHashHex;
        final VerifyReport failure;

        private CanonicalAndHash(byte[] entryHashBytes, String expectedEntryHashHex, VerifyReport failure) {
            this.entryHashBytes = entryHashBytes;
            this.expectedEntryHashHex = expectedEntryHashHex;
            this.failure = failure;
        }

        static CanonicalAndHash fail(VerifyReport r) {
            return new CanonicalAndHash(null, null, r);
        }

        static CanonicalAndHash ok(byte[] bytes, String expectedHex) {
            return new CanonicalAndHash(bytes, expectedHex, null);
        }
    }

    private CanonicalAndHash canonicalizeAndHash(JsonNode signed, Frame f) throws VeriLogException {
        final String canonicalPayload;
        try {
            canonicalPayload = canonicalizeWithout(signed);
        } catch (VeriLogJsonException e) {
            // unexpected (library/JSON issue)
            throw e;
        }

        byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
        String computedEntryHashHex = CryptoUtil.toHexLower(entryHashBytes);

        String expectedEntryHashHex = signed.get(ENTRY_HASH).asText();
        if (!computedEntryHashHex.equals(expectedEntryHashHex)) {
            return CanonicalAndHash.fail(VerifyReport.fail(f.seq, "entryHash mismatch"));
        }

        return CanonicalAndHash.ok(entryHashBytes, expectedEntryHashHex);
    }

    private ECPublicKeyParameters resolveKeyOrFail(JsonNode signed, PublicKeyResolver keyResolver, Frame f) {
        String keyId = signed.get("keyId").asText();
        ECPublicKeyParameters pub = keyResolver.resolveByKeyIdHex(keyId);
        if (pub == null) {
            // expected verification failure
            return null;
        }
        return pub;
    }

    private byte[] decodeSignatureOrFail(JsonNode signed, Frame f) {
        try {
            return Base64.getDecoder().decode(signed.get("sig").asText());
        } catch (IllegalArgumentException e) {
            // expected verification failure
            return null;
        }
    }


    public DirectoryVerifyReport verifyDirectory(Path logDir, byte[] dek32, PublicKeyResolver keyResolver)
            throws VeriLogException {
        return verifyDirectory(logDir, dek32, keyResolver, true);
    }

    /**
     * @param stopOnFirstFailure if true: stop at first failed file
     */
    public DirectoryVerifyReport verifyDirectory(
            Path logDir,
            byte[] dek32,
            PublicKeyResolver keyResolver,
            boolean stopOnFirstFailure
    ) throws VeriLogException {

        Objects.requireNonNull(logDir, "logDir");
        Objects.requireNonNull(dek32, "dek32");
        Objects.requireNonNull(keyResolver, "keyResolver");

        var report = new DirectoryVerifyReport();

        var files = listVlogFiles(logDir);
        sortVlogFiles(files);

        for (Path f : files) {
            boolean tolerate = isCurrentVlog(f);
            VerifyReport r = verifyFile(f, dek32, keyResolver, tolerate);

            report.add(new DirectoryVerifyReport.FileResult(f, r.valid, r.seq, r.reason));

            if (stopOnFirstFailure && !r.valid) break;
        }
        return report;
    }

    private static java.util.List<Path> listVlogFiles(Path logDir) throws VeriLogException {
        java.util.List<Path> files = new java.util.ArrayList<>();
        try (var stream = java.nio.file.Files.list(logDir)) {
            stream
                    .filter(java.nio.file.Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".vlog"))
                    .forEach(files::add);
        } catch (java.io.IOException e) {
            throw new VeriLogIoException("io.read_failed", e, logDir.toString());
        }
        return files;
    }

    private static void sortVlogFiles(java.util.List<Path> files) {
        // One comparator instead of two sorts
        files.sort(
                java.util.Comparator
                        .comparing((Path p) -> p.getFileName().toString().equals(CURRENT_VLOG)) // false first, current last
                        .thenComparing(p -> p.getFileName().toString())
        );
    }

    private static boolean isCurrentVlog(Path p) {
        return p.getFileName().toString().equals(CURRENT_VLOG);
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