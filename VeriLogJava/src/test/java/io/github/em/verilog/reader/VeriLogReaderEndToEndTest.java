package io.github.em.verilog.reader;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.em.verilog.CanonicalJson;
import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.crypto.XChaCha20Poly1305;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class VeriLogReaderEndToEndTest {

    private static final ObjectMapper OM = new ObjectMapper();
    private static final SecureRandom RNG = new SecureRandom();

    @Test
    void should_verify_ok_when_file_contains_valid_signed_hash_chained_entries() throws Exception {
        TestMaterial tm = new TestMaterial();

        Path dir = Files.createTempDirectory("vlog-ok");
        Path file = dir.resolve("current.vlog");

        writeVlogFile(file, "VeriLog|v1", tm.dek32,
                new EntrySpec(1, "0".repeat(64), "user.login", OM.createObjectNode().put("u", "123")),
                new EntrySpec(2, null,              "user.logout", OM.createObjectNode().put("u", "123"))
                , tm);

        VeriLogReader r = new VeriLogReader();
        VerifyReport rep = r.verifyFile(file, tm.dek32, tm.keyResolver);

        assertTrue(rep.ok);
        assertEquals(2, rep.seq);
        assertNull(rep.reason);
    }

    @Test
    void should_fail_when_ciphertext_is_tampered_and_authentication_fails() throws Exception {
        TestMaterial tm = new TestMaterial();

        Path dir = Files.createTempDirectory("vlog-tamper-ct");
        Path file = dir.resolve("current.vlog");

        writeVlogFile(file, "VeriLog|v1", tm.dek32,
                new EntrySpec(1, "0".repeat(64), "evt", OM.createObjectNode().put("x", 1))
                , tm);

        // Flip 1 byte in the payload ciphertext (after header).
        byte[] all = Files.readAllBytes(file);
        int headerLenTotal = headerLenTotal(all);
        // After header, layout is: len(4) + payload. We flip near the end of file (inside ct/tag).
        int flipIndex = Math.min(all.length - 10, headerLenTotal + 4 + 1 + 8 + 24 + 5);
        all[flipIndex] ^= 0x01;
        Files.write(file, all, StandardOpenOption.TRUNCATE_EXISTING);

        VeriLogReader r = new VeriLogReader();
        VerifyReport rep = r.verifyFile(file, tm.dek32, tm.keyResolver);

        assertFalse(rep.ok);
        assertEquals(1, rep.seq);
        assertNotNull(rep.reason);
        assertTrue(rep.reason.contains("decrypt") || rep.reason.contains("auth"));
    }

    @Test
    void should_fail_when_prev_hash_is_wrong_and_chain_breaks() throws Exception {
        TestMaterial tm = new TestMaterial();

        Path dir = Files.createTempDirectory("vlog-bad-prevhash");
        Path file = dir.resolve("current.vlog");

        // Entry 2 is forced to carry a wrong prevHash (we pass it explicitly).
        writeVlogFile(file, "VeriLog|v1", tm.dek32,
                new EntrySpec(1, "0".repeat(64), "evt1", OM.createObjectNode().put("x", 1)),
                new EntrySpec(2, "f".repeat(64), "evt2", OM.createObjectNode().put("x", 2)) // WRONG
                , tm);

        VeriLogReader r = new VeriLogReader();
        VerifyReport rep = r.verifyFile(file, tm.dek32, tm.keyResolver);

        assertFalse(rep.ok);
        assertEquals(2, rep.seq);
        assertEquals("prevHash mismatch", rep.reason);
    }

    @Test
    void should_fail_when_signature_is_invalid() throws Exception {
        TestMaterial tm = new TestMaterial();

        Path dir = Files.createTempDirectory("vlog-bad-sig");
        Path file = dir.resolve("current.vlog");

        writeVlogFile(file, "VeriLog|v1", tm.dek32,
                new EntrySpec(1, "0".repeat(64), "evt", OM.createObjectNode().put("x", 1))
                , tm);

        // Tamper the Base64 "sig" inside plaintext by rewriting frame with a bad sig but valid AEAD.
        // Easiest: rebuild the file with a forged signature (still encrypted correctly).
        Files.delete(file);

        // Create a good entry object, then overwrite signature bytes before encrypting.
        ObjectNode unsigned = buildUnsignedEntry(1, "0".repeat(64), tm.keyIdHex, "evt", OM.createObjectNode().put("x", 1));
        SignedPayload sp = signEntry(unsigned, tm, true /*forceBadSig*/);

        writeVlogFileRawEntries(file, "VeriLog|v1", tm.dek32, tm, new RawEntry(1, sp.json));

        VeriLogReader r = new VeriLogReader();
        VerifyReport rep = r.verifyFile(file, tm.dek32, tm.keyResolver);

        assertFalse(rep.ok);
        assertEquals(1, rep.seq);
        assertEquals("signature invalid", rep.reason);
    }

    @Test
    void should_fail_when_frame_sequence_is_not_contiguous() throws Exception {
        TestMaterial tm = new TestMaterial();

        Path dir = Files.createTempDirectory("vlog-bad-seq");
        Path file = dir.resolve("current.vlog");

        // We'll write entries seq 1 and 3 (gap).
        ObjectNode u1 = buildUnsignedEntry(1, "0".repeat(64), tm.keyIdHex, "evt1", OM.createObjectNode().put("x", 1));
        SignedPayload s1 = signEntry(u1, tm, false);

        ObjectNode u3 = buildUnsignedEntry(3, s1.entryHashHex, tm.keyIdHex, "evt3", OM.createObjectNode().put("x", 3));
        SignedPayload s3 = signEntry(u3, tm, false);

        writeVlogFileRawEntries(file, "VeriLog|v1", tm.dek32, tm,
                new RawEntry(1, s1.json),
                new RawEntry(3, s3.json)
        );

        VeriLogReader r = new VeriLogReader();
        VerifyReport rep = r.verifyFile(file, tm.dek32, tm.keyResolver);

        assertFalse(rep.ok);
        assertEquals(3, rep.seq);
        assertNotNull(rep.reason);
        assertTrue(rep.reason.contains("not contiguous"));
    }

    @Test
    void should_verify_directory_ok_when_multiple_vlog_files_are_valid() throws Exception {
        TestMaterial tm = new TestMaterial();

        Path dir = Files.createTempDirectory("vlog-dir-ok");
        Path f1 = dir.resolve("app-2026-01-01T00-00-00Z.vlog");
        Path f2 = dir.resolve("current.vlog");

        writeVlogFile(f1, "VeriLog|v1", tm.dek32,
                new EntrySpec(1, "0".repeat(64), "evt", OM.createObjectNode().put("a", 1))
                , tm);

        writeVlogFile(f2, "VeriLog|v1", tm.dek32,
                new EntrySpec(1, "0".repeat(64), "evt", OM.createObjectNode().put("b", 2))
                , tm);

        VeriLogReader r = new VeriLogReader();
        DirectoryVerifyReport rep = r.verifyDirectory(dir, tm.dek32, tm.keyResolver, true);

        assertTrue(rep.allOk());
        assertEquals(2, rep.results().size());
        assertTrue(rep.results().stream().allMatch(x -> x.ok));
    }

    // --------------------------------------------------------------------------------------------
    // Helpers / Test material
    // --------------------------------------------------------------------------------------------

    private static final class EntrySpec {
        final long seq;
        final String forcedPrevHashHex; // if null, auto chain from previous entry
        final String eventType;
        final ObjectNode event;

        EntrySpec(long seq, String forcedPrevHashHex, String eventType, ObjectNode event) {
            this.seq = seq;
            this.forcedPrevHashHex = forcedPrevHashHex;
            this.eventType = eventType;
            this.event = event;
        }
    }

    private static final class RawEntry {
        final long frameSeq;
        final byte[] plaintextJsonUtf8;
        RawEntry(long frameSeq, byte[] plaintextJsonUtf8) {
            this.frameSeq = frameSeq;
            this.plaintextJsonUtf8 = plaintextJsonUtf8;
        }
    }

    private static final class SignedPayload {
        final byte[] json;
        final String entryHashHex;
        SignedPayload(byte[] json, String entryHashHex) {
            this.json = json;
            this.entryHashHex = entryHashHex;
        }
    }

    private static final class TestMaterial {
        final byte[] dek32 = randomBytes(32);

        final ECDomainParameters domain;
        final ECPrivateKeyParameters priv;
        final ECPublicKeyParameters pub;

        final String keyIdHex = "test-key-01";
        final PublicKeyResolver keyResolver;

        TestMaterial() {
            // P-256 / secp256r1
            var x9 = NISTNamedCurves.getByName("P-256");
            this.domain = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());

            ECKeyPairGenerator gen = new ECKeyPairGenerator();
            gen.init(new ECKeyGenerationParameters(domain, RNG));
            AsymmetricCipherKeyPair kp = gen.generateKeyPair();

            this.priv = (ECPrivateKeyParameters) kp.getPrivate();
            this.pub  = (ECPublicKeyParameters) kp.getPublic();

            this.keyResolver = new MapPublicKeyResolver(Map.of(keyIdHex, pub));
        }
    }

    private static void writeVlogFile(Path out,
                                      String aadPrefix,
                                      byte[] dek32,
                                      EntrySpec[] entries,
                                      TestMaterial tm) throws Exception {

        String prevHash = "0".repeat(64);

        RawEntry[] raws = new RawEntry[entries.length];

        for (int i = 0; i < entries.length; i++) {
            EntrySpec e = entries[i];

            String prev = (e.forcedPrevHashHex != null) ? e.forcedPrevHashHex : prevHash;

            ObjectNode unsigned = buildUnsignedEntry(e.seq, prev, tm.keyIdHex, e.eventType, e.event);
            SignedPayload sp = signEntry(unsigned, tm, false);

            raws[i] = new RawEntry(e.seq, sp.json);
            prevHash = sp.entryHashHex;
        }

        writeVlogFileRawEntries(out, aadPrefix, dek32, tm, raws);
    }

    private static void writeVlogFile(Path out,
                                      String aadPrefix,
                                      byte[] dek32,
                                      EntrySpec e1,
                                      TestMaterial tm) throws Exception {
        writeVlogFile(out, aadPrefix, dek32, new EntrySpec[]{e1}, tm);
    }

    private static void writeVlogFile(Path out,
                                      String aadPrefix,
                                      byte[] dek32,
                                      EntrySpec e1,
                                      EntrySpec e2,
                                      TestMaterial tm) throws Exception {
        writeVlogFile(out, aadPrefix, dek32, new EntrySpec[]{e1, e2}, tm);
    }

    private static void writeVlogFileRawEntries(Path out,
                                                String aadPrefix,
                                                byte[] dek32,
                                                TestMaterial tm,
                                                RawEntry... entries) throws Exception {

        byte[] headerJson = OM.createObjectNode()
                .put("aad", aadPrefix)
                .toString()
                .getBytes(StandardCharsets.UTF_8);

        try (var ch = FileChannel.open(out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            // Fixed header: magic(4) version(1) flags(1) headerLen(2)
            ByteBuffer fixed = ByteBuffer.allocate(4 + 1 + 1 + 2).order(ByteOrder.BIG_ENDIAN);
            fixed.put((byte) 'V').put((byte) 'L').put((byte) 'O').put((byte) 'G');
            fixed.put((byte) 1);      // version
            fixed.put((byte) 0);      // flags
            fixed.putShort((short) headerJson.length);
            fixed.flip();
            ch.write(fixed);
            ch.write(ByteBuffer.wrap(headerJson));

            byte[] aadPrefixBytes = aadPrefix.getBytes(StandardCharsets.UTF_8);

            for (RawEntry e : entries) {
                byte type = 1;
                long seq = e.frameSeq;

                byte[] nonce24 = randomBytes(24);
                byte[] aad = buildAad(aadPrefixBytes, type, seq);

                byte[] ct = XChaCha20Poly1305.encrypt(dek32, nonce24, e.plaintextJsonUtf8, aad);

                // payload = type(1) + seq(8) + nonce(24) + ct
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
    }

    private static ObjectNode buildUnsignedEntry(long seq,
                                                 String prevHashHex,
                                                 String keyIdHex,
                                                 String eventType,
                                                 ObjectNode event) {
        ObjectNode n = OM.createObjectNode();
        n.put("version", 1);
        n.put("seq", seq);
        n.put("ts", "2026-02-20T00:00:00Z");
        n.put("actor", "test");
        n.put("eventType", eventType);
        n.set("event", event);
        n.put("prevHash", prevHashHex);
        n.put("keyId", keyIdHex);
        return n;
    }

    private static SignedPayload signEntry(ObjectNode unsigned, TestMaterial tm, boolean forceBadSig) throws Exception {
        String canonicalPayload = CanonicalJson.canonicalize(unsigned);
        byte[] entryHash32 = CryptoUtil.sha256Utf8(canonicalPayload);
        String entryHashHex = CryptoUtil.toHexLower(entryHash32);

        byte[] sigRaw64 = signEntryHashLikeWriter(entryHash32, tm.priv);
        if (forceBadSig) sigRaw64[0] ^= 0x01;

        ObjectNode signed = unsigned.deepCopy();
        signed.put("entryHash", entryHashHex);
        signed.put("sig", Base64.getEncoder().encodeToString(sigRaw64));

        return new SignedPayload(OM.writeValueAsBytes(signed), entryHashHex);
    }

    /**
     * Must match reader verifier expectations:
     * verifier computes digest = SHA256(entryHash32) and verifies ECDSA over that digest.
     */
    private static byte[] signEntryHashLikeWriter(byte[] entryHash32, ECPrivateKeyParameters priv) {
        if (entryHash32 == null || entryHash32.length != 32) throw new IllegalArgumentException();

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

    private static byte[] toFixed32(java.math.BigInteger x) {
        byte[] b = x.toByteArray();
        // BigInteger may produce 33 bytes with leading 0; or fewer.
        byte[] out = new byte[32];
        int srcPos = Math.max(0, b.length - 32);
        int len = Math.min(32, b.length);
        System.arraycopy(b, srcPos, out, 32 - len, len);
        return out;
    }

    private static byte[] buildAad(byte[] prefix, byte type, long seq) {
        // Must match VeriLogReader.buildAad()
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

    /**
     * Recompute FramedFileReader's headerLenTotal from raw bytes.
     * Header: magic(4) ver(1) flags(1) headerLen(2) + headerLen bytes.
     */
    private static int headerLenTotal(byte[] all) {
        if (all.length < 8) throw new IllegalArgumentException("too small");
        int headerLen = ByteBuffer.wrap(all, 6, 2).order(ByteOrder.BIG_ENDIAN).getShort() & 0xFFFF;
        return (4 + 1 + 1 + 2) + headerLen;
    }
}