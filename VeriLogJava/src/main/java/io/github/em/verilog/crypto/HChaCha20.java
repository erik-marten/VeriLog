package io.github.em.verilog.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

final class HChaCha20 {
    private HChaCha20() {}

    static byte[] subKey(byte[] key32, byte[] nonce16) {
        if (key32.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
        if (nonce16.length != 16) throw new IllegalArgumentException("nonce must be 16 bytes");

        int[] x = new int[16];

        x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;

        for (int i = 0; i < 8; i++) x[4 + i] = leInt(key32, i * 4);
        for (int i = 0; i < 4; i++) x[12 + i] = leInt(nonce16, i * 4);

        for (int i = 0; i < 10; i++) {
            qr(x, 0, 4, 8, 12);  qr(x, 1, 5, 9, 13);  qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15);
            qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13);  qr(x, 3, 4, 9, 14);
        }

        byte[] out = new byte[32];
        lePut(x[0], out, 0);  lePut(x[1], out, 4);  lePut(x[2], out, 8);  lePut(x[3], out, 12);
        lePut(x[12], out, 16); lePut(x[13], out, 20); lePut(x[14], out, 24); lePut(x[15], out, 28);
        return out;
    }

    private static void qr(int[] x, int a, int b, int c, int d) {
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl(x[d], 16);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl(x[b], 12);
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl(x[d], 8);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl(x[b], 7);
    }

    private static int rotl(int v, int n) { return (v << n) | (v >>> (32 - n)); }
    private static int leInt(byte[] b, int off) {
        return ByteBuffer.wrap(b, off, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }
    private static void lePut(int v, byte[] out, int off) {
        ByteBuffer.wrap(out, off, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(v);
    }
}