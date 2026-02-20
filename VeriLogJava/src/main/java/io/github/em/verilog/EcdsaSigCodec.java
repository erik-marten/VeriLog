package io.github.em.verilog;

import java.util.Arrays;

public final class EcdsaSigCodec {
    private EcdsaSigCodec() {}

    // raw: 64 bytes r||s (each 32 bytes big-endian)
    public static byte[] rawToDer(byte[] raw64) {
        if (raw64.length != 64) throw new IllegalArgumentException("Expected 64-byte raw signature");
        byte[] r = Arrays.copyOfRange(raw64, 0, 32);
        byte[] s = Arrays.copyOfRange(raw64, 32, 64);

        byte[] rEnc = encodeAsn1IntUnsigned(r);
        byte[] sEnc = encodeAsn1IntUnsigned(s);

        int len = 2 + rEnc.length + 2 + sEnc.length;
        if (len > 127) throw new IllegalArgumentException("DER length too large for short form");

        byte[] out = new byte[2 + len];
        out[0] = 0x30; // SEQUENCE
        out[1] = (byte) len;

        int i = 2;
        out[i++] = 0x02; out[i++] = (byte) rEnc.length;
        System.arraycopy(rEnc, 0, out, i, rEnc.length); i += rEnc.length;

        out[i++] = 0x02; out[i++] = (byte) sEnc.length;
        System.arraycopy(sEnc, 0, out, i, sEnc.length);

        return out;
    }

    // Minimal DER parser for SEQUENCE(INTEGER r, INTEGER s)
    public static byte[] derToRaw(byte[] der) {
        if (der.length < 8 || der[0] != 0x30) throw new IllegalArgumentException("Not a DER SEQUENCE");
        int idx = 2; // assumes short-form length

        if (der[idx++] != 0x02) throw new IllegalArgumentException("Expected INTEGER");
        int rLen = der[idx++] & 0xFF;
        byte[] r = Arrays.copyOfRange(der, idx, idx + rLen); idx += rLen;

        if (der[idx++] != 0x02) throw new IllegalArgumentException("Expected INTEGER");
        int sLen = der[idx++] & 0xFF;
        byte[] s = Arrays.copyOfRange(der, idx, idx + sLen);

        return concat(pad32(stripLeadingZero(r)), pad32(stripLeadingZero(s)));
    }

    private static byte[] encodeAsn1IntUnsigned(byte[] be) {
        byte[] stripped = stripLeadingZeroes(be);
        if (stripped.length == 0) stripped = new byte[]{0x00};

        // If MSB is set, prefix 0x00 to keep integer positive
        if ((stripped[0] & 0x80) != 0) {
            byte[] pref = new byte[stripped.length + 1];
            pref[0] = 0x00;
            System.arraycopy(stripped, 0, pref, 1, stripped.length);
            return pref;
        }
        return stripped;
    }

    private static byte[] stripLeadingZeroes(byte[] be) {
        int i = 0;
        while (i < be.length - 1 && be[i] == 0x00) i++;
        return Arrays.copyOfRange(be, i, be.length);
    }

    private static byte[] stripLeadingZero(byte[] x) {
        if (x.length > 1 && x[0] == 0x00) return Arrays.copyOfRange(x, 1, x.length);
        return x;
    }

    private static byte[] pad32(byte[] be) {
        if (be.length > 32) throw new IllegalArgumentException("Integer too large for P-256");
        byte[] out = new byte[32];
        System.arraycopy(be, 0, out, 32 - be.length, be.length);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}