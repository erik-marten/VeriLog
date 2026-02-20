package io.github.em.verilog.reader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.em.verilog.CanonicalJson;
import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.crypto.XChaCha20Poly1305;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

public final class VeriLogReader {

    private final ObjectMapper om = new ObjectMapper();

    public VerifyReport verifyFile(Path vlogPath, byte[] dek32, PublicKeyResolver keyResolver) throws Exception {
        return verifyFile(vlogPath, dek32, keyResolver, false);
    }

    public VerifyReport verifyFile(Path vlogPath, byte[] dek32, PublicKeyResolver keyResolver, boolean tolerateTrailingPartialFrame)
            throws Exception {
        long expectedSeq = 1;
        String prevHashExpected = "0".repeat(64);
        long lastOk = 0;

        try (FramedFileReader r = new FramedFileReader(vlogPath)) {
            String headerJson = new String(r.rawHeaderJsonBytes(), StandardCharsets.UTF_8);
            JsonNode header = om.readTree(headerJson);
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

                byte[] plaintext;
                try {
                    plaintext = XChaCha20Poly1305.decrypt(dek32, f.nonce24, f.ct, aad);
                } catch (InvalidCipherTextException e) {
                    return VerifyReport.fail(f.seq, "decrypt/auth failed");
                }

                JsonNode signed = om.readTree(new String(plaintext, StandardCharsets.UTF_8));

                long jsonSeq = signed.get("seq").asLong();
                if (jsonSeq != f.seq) {
                    return VerifyReport.fail(f.seq, "json seq mismatch (json=" + jsonSeq + ")");
                }

                String prevHash = signed.get("prevHash").asText();
                if (!prevHash.equals(prevHashExpected)) {
                    return VerifyReport.fail(f.seq, "prevHash mismatch");
                }

                String canonicalPayload = canonicalizeWithout(signed);
                byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
                String computedEntryHashHex = CryptoUtil.toHexLower(entryHashBytes);

                String expectedEntryHashHex = signed.get("entryHash").asText();
                if (!computedEntryHashHex.equals(expectedEntryHashHex)) {
                    return VerifyReport.fail(f.seq, "entryHash mismatch");
                }

                String keyId = signed.get("keyId").asText();
                ECPublicKeyParameters pub = keyResolver.resolveByKeyIdHex(keyId);
                if (pub == null) return VerifyReport.fail(f.seq, "unknown keyId: " + keyId);

                byte[] sigRaw = Base64.getDecoder().decode(signed.get("sig").asText());
                boolean sigOk = BcEcdsaVerifier.verifyEntryHashSig(pub, entryHashBytes, sigRaw);
                if (!sigOk) return VerifyReport.fail(f.seq, "signature invalid");

                prevHashExpected = expectedEntryHashHex;
                expectedSeq++;
                lastOk = f.seq;
            }
        }

        return VerifyReport.ok(lastOk);
    }

    public DirectoryVerifyReport verifyDirectory(Path logDir, byte[] dek32, PublicKeyResolver keyResolver) throws Exception {
        return verifyDirectory(logDir, dek32, keyResolver, true);
    }

    /**
     * @param stopOnFirstFailure if true: stop at first failed file
     */
    public DirectoryVerifyReport verifyDirectory(Path logDir, byte[] dek32, PublicKeyResolver keyResolver, boolean stopOnFirstFailure)
            throws Exception {

        if (logDir == null) throw new NullPointerException("logDir");

        var report = new DirectoryVerifyReport();

        // list *.vlog, skip directories
        java.util.List<java.nio.file.Path> files = new java.util.ArrayList<>();
        try (var stream = java.nio.file.Files.list(logDir)) {
            stream
                    .filter(p -> java.nio.file.Files.isRegularFile(p))
                    .filter(p -> p.getFileName().toString().endsWith(".vlog"))
                    .forEach(files::add);
        }

        // Sort: prefer name sort (works well with your prefix-timestamp naming), fallback to lastModified
        files.sort((a, b) -> {
            int c = a.getFileName().toString().compareTo(b.getFileName().toString());
            if (c != 0) return c;
            try {
                long ta = java.nio.file.Files.getLastModifiedTime(a).toMillis();
                long tb = java.nio.file.Files.getLastModifiedTime(b).toMillis();
                return Long.compare(ta, tb);
            } catch (Exception e) {
                return 0;
            }
        });

        files.sort((a, b) -> {
            String an = a.getFileName().toString();
            String bn = b.getFileName().toString();
            boolean ac = an.equals("current.vlog");
            boolean bc = bn.equals("current.vlog");
            if (ac == bc) return 0;
            return ac ? 1 : -1; // current last
        });

        for (var f : files) {
            boolean tolerate = f.getFileName().toString().equals("current.vlog");
            VerifyReport r = verifyFile(f, dek32, keyResolver, tolerate);

            report.add(new DirectoryVerifyReport.FileResult(f, r.ok, r.seq, r.reason));

            if (!r.ok && stopOnFirstFailure) break;
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

    private String canonicalizeWithout(JsonNode obj) throws Exception {
        // Create a mutable copy as ObjectNode, remove fields, then canonicalize via CanonicalJson
        var copy = obj.deepCopy();
        if (copy.isObject()) {
            for (String r : new String[]{"entryHash", "sig"}) ((com.fasterxml.jackson.databind.node.ObjectNode) copy).remove(r);
        }
        return CanonicalJson.canonicalize(copy);
    }
}