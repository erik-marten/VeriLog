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
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

public final class VeriLogReader {

    private final ObjectMapper om = new ObjectMapper();
    private static final String ENTRY_HASH = "entryHash";
    private static final String CURRENT_VLOG = "current.vlog";

    /**
     * Verifies a standalone chain root, starting at sequence 1 and the zero previous hash.
     * A middle rotated file must be verified with its preceding files via verifyDirectory.
     */
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
        return verifyFileWithState(vlogPath, dek32, keyResolver, tolerateTrailingPartialFrame, new State());
    }

    private VerifyReport verifyFileWithState(
            Path vlogPath,
            byte[] dek32,
            PublicKeyResolver keyResolver,
            boolean tolerateTrailingPartialFrame,
            State s
    ) throws VeriLogException {
        try (FramedFileReader r = new FramedFileReader(vlogPath)) {
            final Header h = readHeader(r, vlogPath);

            r.positionAtFirstFrame();

            Frame f;
            while ((f = r.readNextFrame(tolerateTrailingPartialFrame)) != null) {
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
            Frame frame,
            State state,
            Header header,
            byte[] dek32,
            PublicKeyResolver keyResolver
    ) throws VeriLogException {

        VerifyReport report;

        if ((report = verifyFrameMeta(frame, state.expectedSeq)) != null) return report;

        final byte[] aad = buildAad(header.aadPrefixBytes, frame.type, frame.seq);

        final byte[] plaintext;
        try {
            plaintext = XChaCha20Poly1305.decrypt(dek32, frame.nonce24, frame.ct, aad);
        } catch (InvalidCipherTextException e) {
            return VerifyReport.fail(frame.seq, "decrypt/auth failed");
        }

        final JsonNode signed;
        try {
            signed = om.readTree(new String(plaintext, StandardCharsets.UTF_8));
        } catch (JsonProcessingException e) {
            return VerifyReport.fail(frame.seq, "invalid signed JSON");
        }

        if ((report = verifyRequiredFields(signed, frame)) != null) return report;
        if ((report = verifyJsonSeqMatchesFrame(signed, frame)) != null) return report;
        if ((report = verifyPrevHashMatches(signed, frame, state.prevHashExpected)) != null) return report;

        final CanonicalAndHash ch = canonicalizeAndHash(signed, frame);
        if (ch.failure != null) return ch.failure;

        final ECPublicKeyParameters pub = resolveKeyOrFail(signed, keyResolver);
        if (pub == null) return VerifyReport.fail(frame.seq, "unknown keyId"); // should not happen

        final byte[] sigRaw = decodeSignatureOrFail(signed);
        if (sigRaw == null) return VerifyReport.fail(frame.seq, "signature encoding invalid");

        final boolean sigOk;
        try {
            sigOk = BcEcdsaVerifier.verifyEntryHashSig(pub, ch.entryHashBytes, sigRaw);
        } catch (VeriLogCryptoException e) {
            // unexpected crypto failure (engine/provider/etc)
            throw new VeriLogCryptoException("crypto.verify_failed", e, "seq", String.valueOf(frame.seq));
        }

        if (!sigOk) {
            return VerifyReport.fail(frame.seq, "signature invalid");
        }

        // Update state (single place, after full success)
        state.prevHashExpected = ch.expectedEntryHashHex;
        state.expectedSeq++;
        state.lastOk = frame.seq;

        return null;
    }

    // ---------------------------
    // Header
    // ---------------------------

    private Header readHeader(FramedFileReader r, Path vlogPath) throws VeriLogException {
        final byte[] raw = r.rawHeaderJsonBytes();
        if (raw == null || raw.length == 0) {
            throw new VeriLogFormatException("format.missing_header", vlogPath.toString());
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
        canonicalPayload = canonicalizeWithout(signed);
        byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
        String computedEntryHashHex = CryptoUtil.toHexLower(entryHashBytes);

        String expectedEntryHashHex = signed.get(ENTRY_HASH).asText();
        if (!computedEntryHashHex.equals(expectedEntryHashHex)) {
            return CanonicalAndHash.fail(VerifyReport.fail(f.seq, "entryHash mismatch"));
        }

        return CanonicalAndHash.ok(entryHashBytes, expectedEntryHashHex);
    }

    private ECPublicKeyParameters resolveKeyOrFail(JsonNode signed, PublicKeyResolver keyResolver) {
        String keyId = signed.get("keyId").asText();
        ECPublicKeyParameters pub = keyResolver.resolveByKeyIdHex(keyId);
        if (pub == null) {
            // expected verification failure
            return null;
        }
        return pub;
    }

    @SuppressWarnings("java:S1168")
    private byte[] decodeSignatureOrFail(JsonNode signed) {
        try {
            return Base64.getDecoder().decode(signed.get("sig").asText());
        } catch (IllegalArgumentException e) {
            // expected verification failure
            return null;
        }
    }


    /**
     * Verifies one continuous local chain across the directory's files. This detects
     * internal deletion or reordering while later chain material remains available.
     * Replacing the entire set with an older valid prefix requires an external trusted
     * anchor to detect; the local chain alone does not provide rollback resistance.
     */
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

        List<FileStart> files = new java.util.ArrayList<>();
        for (Path file : listVlogFiles(logDir)) {
            files.add(new FileStart(file, firstFrameSeq(file)));
        }
        files.sort(Comparator
                .comparing((FileStart f) -> f.firstSeq == null)
                .thenComparing(f -> f.firstSeq, Comparator.nullsLast(Long::compareTo))
                .thenComparing(f -> f.path.getFileName().toString()));

        State state = new State();
        for (FileStart file : files) {
            Path f = file.path;
            boolean tolerate = isCurrentVlog(f);
            VerifyReport r = verifyFileWithState(f, dek32, keyResolver, tolerate, state);

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

    private static final class FileStart {
        final Path path;
        final Long firstSeq; // null for a header-only file (or tolerated partial current frame)

        FileStart(Path path, Long firstSeq) {
            this.path = path;
            this.firstSeq = firstSeq;
        }
    }

    private static Long firstFrameSeq(Path file) throws VeriLogException {
        try (FramedFileReader reader = new FramedFileReader(file)) {
            reader.positionAtFirstFrame();
            Frame first = reader.readNextFrame(isCurrentVlog(file));
            return first == null ? null : first.seq;
        } catch (java.io.IOException e) {
            throw new VeriLogIoException("io.read_failed", e, file.toString());
        }
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
        try {
            var copy = obj.deepCopy();
            if (copy.isObject()) {
                for (String r : new String[]{ENTRY_HASH, "sig"}) {
                    ((com.fasterxml.jackson.databind.node.ObjectNode) copy).remove(r);
                }
            }
            return CanonicalJson.canonicalize(copy);

        } catch (RuntimeException e) {
            // unexpected Jackson/runtime issue
            throw new VeriLogJsonException("json.canonicalize_failed", e);
        }
    }
}
