package io.github.em.verilog.logger;

import io.github.em.verilog.errors.VeriLogCryptoException;
import io.github.em.verilog.sign.LogSigner;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

final class TestLogSigner implements LogSigner {

    private final PrivateKey priv;
    private final String keyId;

    TestLogSigner(PrivateKey priv, PublicKey pub) {
        this.priv = priv;
        this.keyId = computeKeyId(pub);
    }

    @Override
    public String keyId() {
        return keyId;
    }

    @Override
    public byte[] signEntryHash(byte[] entryHash32) throws VeriLogCryptoException {
        if (entryHash32 == null || entryHash32.length != 32) {
            throw new VeriLogCryptoException("crypto.bad_entry_hash");
        }

        try {
            // Sign the *hash* directly
            Signature s = Signature.getInstance("NONEwithECDSA");
            s.initSign(priv);
            s.update(entryHash32);
            byte[] der = s.sign();
            return derToRaw64(der);
        } catch (Exception e) {
            throw new VeriLogCryptoException("crypto.sign_failed", e);
        }
    }

    private static String computeKeyId(PublicKey pub) {
        try {
            byte[] spkiDer = pub.getEncoded(); // SubjectPublicKeyInfo DER
            byte[] h = MessageDigest.getInstance("SHA-256").digest(spkiDer);
            return Arrays.toString(Hex.encode(h));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] derToRaw64(byte[] der) throws IOException {
        try (ASN1InputStream in = new ASN1InputStream(der)) {
            ASN1Primitive p = in.readObject();
            ASN1Sequence seq = ASN1Sequence.getInstance(p);
            if (seq.size() != 2) throw new IOException("Bad ECDSA DER sequence");

            byte[] r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().toByteArray();
            byte[] s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().toByteArray();

            byte[] out = new byte[64];
            writeUnsignedFixed32(r, out, 0);
            writeUnsignedFixed32(s, out, 32);
            return out;
        }
    }

    private static void writeUnsignedFixed32(byte[] v, byte[] out, int off) throws IOException {
        // ASN.1 INTEGER may be signed; strip leading 0x00 if present.
        int start = 0;
        while (start < v.length - 1 && v[start] == 0x00) start++;
        int len = v.length - start;
        if (len > 32) throw new IOException("Integer too large for P-256");

        // left pad with zeros to 32 bytes
        int pad = 32 - len;
        for (int i = 0; i < pad; i++) out[off + i] = 0;
        System.arraycopy(v, start, out, off + pad, len);
    }
}