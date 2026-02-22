package io.github.em.verilog.reader;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.em.verilog.CanonicalJson;
import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.crypto.XChaCha20Poly1305;
import io.github.em.verilog.errors.VeriLogCryptoException;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.*;

final class TestFiles {

    private static final ObjectMapper OM = new ObjectMapper();
    private static final SecureRandom RNG = new SecureRandom();

    static final byte[] DEK_ZERO_32 = new byte[32];

    private static volatile Path ROOT;
    private static volatile TestMaterial TM; // used for signature-valid/invalid cases

    private TestFiles() {
    }

    static TestMaterial material() {
        if (TM == null) {
            synchronized (TestFiles.class) {
                if (TM == null) TM = new TestMaterial();
            }
        }
        return TM;
    }

    static Path invalidHeaderFile() {
        return cached("invalid_header.vlog", TestFiles::writeInvalidHeaderFile);
    }

    static Path encryptedWithWrongKey() {
        // encrypted with random DEK, reader will be given DEK_ZERO_32 -> decrypt/auth failed
        return cached("decrypt_fail_wrong_key.vlog", p -> {
            byte[] wrongDek = randomBytes(32);
            writeVlogFileSingleEntry(
                    p,
                    "VeriLog|v1",
                    wrongDek,
                    // Make plaintext a valid signed-ish JSON- doesn’t matter, decrypt will fail
                    signedJsonUtf8(1, "0".repeat(64), "unknown-key", false, null),
                    1
            );
        });
    }

    static Path directoryWithInvalidHeaderFirst() {
        return cachedDir("dir_invalid_header_first", dir -> {

            // First file (lexicographically smallest)
            Files.copy(
                    invalidHeaderFile(),
                    dir.resolve("a-0001.vlog"),
                    REPLACE_EXISTING
            );

            // Add another valid-ish file to prove it never gets processed
            Files.copy(
                    validButUnknownKeyId(),
                    dir.resolve("b-0002.vlog"),
                    REPLACE_EXISTING
            );

            Files.copy(
                    validButUnknownKeyId(),
                    dir.resolve("current.vlog"),
                    REPLACE_EXISTING
            );
        });
    }

    static Path validButUnknownKeyId() {
        return cached("unknown_keyid.vlog", p -> {
            // decrypt works (DEK_ZERO_32), but key resolver returns null => "unknown keyId"
            byte[] plaintext = signedJsonUtf8(
                    1,
                    "0".repeat(64),
                    "deadbeef",           // unknown keyId
                    false,                // signature not checked because keyId unknown- still keep it parseable
                    null
            );
            writeVlogFileSingleEntry(p, "VeriLog|v1", DEK_ZERO_32, plaintext, 1);
        });
    }

    static Path tamperedSignature() {
        // Needs a resolver that actually returns a public key, otherwise it fails earlier with "unknown keyId"
        return cached("bad_signature.vlog", p -> {
            TestMaterial tm = material();
            byte[] plaintext = signedJsonUtf8(
                    1,
                    "0".repeat(64),
                    tm.keyIdHex,
                    true,     // force bad signature
                    tm        // sign using tm.priv, then flip a bit
            );
            writeVlogFileSingleEntry(p, "VeriLog|v1", tm.dek32, plaintext, 1);
        });
    }

    static Path directoryWithOneBrokenFile() {
        return cachedDir("dir_one_broken", dir -> {
            // First file: verification failure (returns VerifyReport.fail), not exception
            Files.copy(validButUnknownKeyId(), dir.resolve("a-0001.vlog"), REPLACE_EXISTING);

            // Second file: another file that would be processed if stopOnFirstFailure=false
            Files.copy(validButUnknownKeyId(), dir.resolve("b-0002.vlog"), REPLACE_EXISTING);

            // current.vlog last
            Files.copy(validButUnknownKeyId(), dir.resolve("current.vlog"), REPLACE_EXISTING);
        });
    }

    static Path directoryWithMultipleBrokenFiles() {
        return cachedDir("dir_multiple_broken", dir -> {
            var tm = material(); // provides key + resolver

            // Tamper: signature invalid
            Files.copy(tamperedSignature(), dir.resolve("a-0001.vlog"), REPLACE_EXISTING);

            // Tamper: entryHash mismatch
            Files.copy(entryHashMismatch(tm), dir.resolve("b-0002.vlog"), REPLACE_EXISTING);

            // current.vlog last: decrypt/auth failed (wrong DEK)
            Files.copy(encryptedWithWrongKey(), dir.resolve("current.vlog"), REPLACE_EXISTING);
        });
    }

    // --------------------------------------------------------------------------------------------
    // Core file writing
    // --------------------------------------------------------------------------------------------

    private static void writeInvalidHeaderFile(Path out) throws Exception {
        byte[] badHeader = "not-json".getBytes(StandardCharsets.UTF_8);

        try (var ch = FileChannel.open(out, CREATE, TRUNCATE_EXISTING, WRITE)) {
            ByteBuffer fixed = ByteBuffer.allocate(4 + 1 + 1 + 2).order(ByteOrder.BIG_ENDIAN);
            fixed.put((byte) 'V').put((byte) 'L').put((byte) 'O').put((byte) 'G');
            fixed.put((byte) 1);   // version
            fixed.put((byte) 0);   // flags
            fixed.putShort((short) badHeader.length);
            fixed.flip();

            ch.write(fixed);
            ch.write(ByteBuffer.wrap(badHeader));
        }
    }

    private static void writeVlogFileSingleEntry(Path out,
                                                 String aadPrefix,
                                                 byte[] dek32,
                                                 byte[] plaintextJsonUtf8,
                                                 long frameSeq) throws Exception {

        byte[] headerJson = OM.createObjectNode()
                .put("aad", aadPrefix)
                .toString()
                .getBytes(StandardCharsets.UTF_8);

        try (var ch = FileChannel.open(out, CREATE, TRUNCATE_EXISTING, WRITE)) {
            // Fixed header: magic(4) version(1) flags(1) headerLen(2)
            ByteBuffer fixed = ByteBuffer.allocate(4 + 1 + 1 + 2).order(ByteOrder.BIG_ENDIAN);
            fixed.put((byte) 'V').put((byte) 'L').put((byte) 'O').put((byte) 'G');
            fixed.put((byte) 1);
            fixed.put((byte) 0);
            fixed.putShort((short) headerJson.length);
            fixed.flip();
            ch.write(fixed);
            ch.write(ByteBuffer.wrap(headerJson));

            byte[] aadPrefixBytes = aadPrefix.getBytes(StandardCharsets.UTF_8);

            byte type = 1;
            long seq = frameSeq;

            byte[] nonce24 = randomBytes(24);
            byte[] aad = buildAad(aadPrefixBytes, type, seq);
            byte[] ct = XChaCha20Poly1305.encrypt(dek32, nonce24, plaintextJsonUtf8, aad);

            ByteBuffer payload = ByteBuffer.allocate(1 + 8 + 24 + ct.length).order(ByteOrder.BIG_ENDIAN);
            payload.put(type);
            payload.putLong(seq);
            payload.put(nonce24);
            payload.put(ct);
            payload.flip();

            ByteBuffer len = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            len.putInt(payload.remaining());
            len.flip();

            ch.write(len);
            ch.write(payload);
        }
    }

    // Signed entry JSON (matches reader expectations)
    private static byte[] signedJsonUtf8(long seq,
                                         String prevHashHex,
                                         String keyIdHex,
                                         boolean forceBadSig,
                                         TestMaterial tmOrNull) throws Exception {

        ObjectNode unsigned = OM.createObjectNode();
        unsigned.put("version", 1);
        unsigned.put("seq", seq);
        unsigned.put("ts", "2026-02-20T00:00:00Z");
        unsigned.put("actor", "test");
        unsigned.put("eventType", "evt");
        unsigned.set("event", OM.createObjectNode().put("x", 1));
        unsigned.put("prevHash", prevHashHex);
        unsigned.put("keyId", keyIdHex);

        String canonicalPayload = CanonicalJson.canonicalize(unsigned);
        byte[] entryHash32 = CryptoUtil.sha256Utf8(canonicalPayload);
        String entryHashHex = CryptoUtil.toHexLower(entryHash32);

        byte[] sigRaw64;
        if (tmOrNull != null) {
            sigRaw64 = signEntryHashLikeWriter(entryHash32, tmOrNull.priv);
            if (forceBadSig) sigRaw64[0] ^= 0x01;
        } else {
            // still parseable base64; may never be verified (e.g., unknown keyId)
            sigRaw64 = new byte[64];
            if (forceBadSig) sigRaw64[0] = 1;
        }

        ObjectNode signed = unsigned.deepCopy();
        signed.put("entryHash", entryHashHex);
        signed.put("sig", Base64.getEncoder().encodeToString(sigRaw64));

        return OM.writeValueAsBytes(signed);
    }

    private static byte[] signEntryHashLikeWriter(byte[] entryHash32, ECPrivateKeyParameters priv) throws VeriLogCryptoException {
        byte[] digest = CryptoUtil.sha256(entryHash32);

        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, priv);
        var rs = signer.generateSignature(digest);

        byte[] r = toFixed32(rs[0]);
        byte[] s = toFixed32(rs[1]);

        byte[] out = new byte[64];
        System.arraycopy(r, 0, out, 0, 32);
        System.arraycopy(s, 0, out, 32, 32);
        return out;
    }

    static Path entryHashMismatch(TestMaterial tm) {
        return cached("entryhash_mismatch.vlog", p -> {
            // Build a normal signed entry (with valid signature for the ORIGINAL hash)
            byte[] plaintext = signedJsonUtf8(
                    1,
                    "0".repeat(64),
                    tm.keyIdHex,
                    false,
                    tm
            );

            // Parse and corrupt the entryHash field AFTER it was computed
            var node = (com.fasterxml.jackson.databind.node.ObjectNode) OM.readTree(plaintext);

            String original = node.get("entryHash").asText();
            // Flip the last hex nibble so it's guaranteed different but still valid hex
            char last = original.charAt(original.length() - 1);
            char flipped = (last != '0') ? '0' : '1';
            String corrupted = original.substring(0, original.length() - 1) + flipped;

            node.put("entryHash", corrupted);

            byte[] corruptedPlaintext = OM.writeValueAsBytes(node);

            // Encrypt/write to a real .vlog file
            writeVlogFileSingleEntry(p, "VeriLog|v1", tm.dek32, corruptedPlaintext, 1);
        });
    }

    private static byte[] toFixed32(java.math.BigInteger x) {
        byte[] b = x.toByteArray();
        byte[] out = new byte[32];
        int srcPos = Math.max(0, b.length - 32);
        int len = Math.min(32, b.length);
        System.arraycopy(b, srcPos, out, 32 - len, len);
        return out;
    }

    private static byte[] buildAad(byte[] prefix, byte type, long seq) {
        ByteBuffer bb = ByteBuffer.allocate(prefix.length + 1 + 8 + 1 + 1).order(ByteOrder.BIG_ENDIAN);
        bb.put(prefix);
        bb.put((byte) 0x00);
        bb.putLong(seq);
        bb.put((byte) 0x00);
        bb.put(type);
        return bb.array();
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    // --------------------------------------------------------------------------------------------
    // Cache helpers (generate once per test run)
    // --------------------------------------------------------------------------------------------

    private interface PathWriter {
        void write(Path p) throws Exception;
    }

    private static Path cached(String name, PathWriter writer) {
        try {
            Path root = root();
            Path p = root.resolve(name);
            if (!Files.exists(p)) {
                writer.write(p);
            }
            return p;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create test file: " + name, e);
        }
    }

    private static Path cachedDir(String name, PathWriter writer) {
        try {
            Path root = root();
            Path dir = root.resolve(name);
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
                writer.write(dir);
            }
            return dir;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create test dir: " + name, e);
        }
    }

    private static Path root() throws Exception {
        if (ROOT == null) {
            synchronized (TestFiles.class) {
                if (ROOT == null) {
                    ROOT = Files.createTempDirectory("verilog-fixtures-");
                }
            }
        }
        return ROOT;
    }

    // --------------------------------------------------------------------------------------------
    // Material for signature verification cases
    // --------------------------------------------------------------------------------------------

    static final class TestMaterial {
        final byte[] dek32 = randomBytes(32);

        final ECDomainParameters domain;
        final ECPrivateKeyParameters priv;
        final ECPublicKeyParameters pub;

        final String keyIdHex;
        final PublicKeyResolver keyResolver;

        TestMaterial() {
            var x9 = NISTNamedCurves.getByName("P-256");
            this.domain = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());

            ECKeyPairGenerator gen = new ECKeyPairGenerator();
            gen.init(new ECKeyGenerationParameters(domain, RNG));
            AsymmetricCipherKeyPair kp = gen.generateKeyPair();

            this.priv = (ECPrivateKeyParameters) kp.getPrivate();
            this.pub = (ECPublicKeyParameters) kp.getPublic();

            // keyId
            this.keyIdHex = "test-key-01";
            this.keyResolver = new MapPublicKeyResolver(Map.of(keyIdHex, pub));
        }
    }
}