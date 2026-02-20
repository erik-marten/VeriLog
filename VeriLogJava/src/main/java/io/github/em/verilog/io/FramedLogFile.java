package io.github.em.verilog.io;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.em.verilog.crypto.XChaCha20Poly1305;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;

public final class FramedLogFile implements Closeable {

    public static final byte TYPE_LOG = 1;

    private static final byte[] MAGIC = new byte[]{'V','L','O','G'};
    private static final int FIXED_HEADER_LEN = 4 + 1 + 1 + 2; // magic + version + flags + headerLen

    private final Path path;
    private final FileChannel ch;
    private final SecureRandom rng;
    private final byte[] dek32;
    private final byte[] aadPrefix; // UTF8(header.aad)

    private long nextSeq; // maintained by logger

    public static FramedLogFile openOrCreate(Path path, byte[] dek32, String aad) throws IOException {
        Files.createDirectories(path.getParent() == null ? Path.of(".") : path.getParent());
        boolean exists = Files.exists(path);
        FileChannel ch = FileChannel.open(path,
                StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);

        FramedLogFile f = new FramedLogFile(path, ch, new SecureRandom(), dek32, aad);

        if (!exists || ch.size() == 0) {
            f.writeHeader();
            f.nextSeq = 1;
        } else {
            f.validateHeaderAndRecover();
            f.nextSeq = f.scanNextSeq(); // basic scan; can be optimized with checkpoints
        }
        ch.position(ch.size());
        return f;
    }

    private FramedLogFile(Path path, FileChannel ch, SecureRandom rng, byte[] dek32, String aad) {
        if (dek32 == null || dek32.length != 32) throw new IllegalArgumentException("DEK must be 32 bytes");
        this.path = path;
        this.ch = ch;
        this.rng = rng;
        this.dek32 = dek32.clone();
        this.aadPrefix = aad.getBytes(StandardCharsets.UTF_8);
    }

    public long nextSeq() { return nextSeq; }

    public void appendEncryptedJson(byte type, long seq, byte[] plaintextUtf8Json) throws IOException {
        byte[] nonce = XChaCha20Poly1305.randomNonce(rng);
        byte[] aad = buildAad(type, seq);
        byte[] ct = XChaCha20Poly1305.encrypt(dek32, nonce, plaintextUtf8Json, aad);

        int payloadLen = 1 + 8 + 24 + ct.length; // type + seq + nonce + ct
        ByteBuffer frame = ByteBuffer.allocate(4 + payloadLen).order(ByteOrder.BIG_ENDIAN);
        frame.putInt(payloadLen);
        frame.put(type);
        frame.putLong(seq);
        frame.put(nonce);
        frame.put(ct);
        frame.flip();

        while (frame.hasRemaining()) ch.write(frame);
        nextSeq = seq + 1;
    }

    public void flush(boolean fsync) throws IOException {
        ch.force(fsync);
    }

    @Override public void close() throws IOException { ch.close(); }

    // ---------------- header + recovery ----------------

    private void writeHeader() throws IOException {
        ObjectMapper om = new ObjectMapper();
        byte flags = 0x01; // encrypted records

        byte[] headerJson = om.writeValueAsBytes(Map.of(
                "v", 1,
                "alg", "XChaCha20-Poly1305",
                "aad", new String(aadPrefix, StandardCharsets.UTF_8),
                "createdAt", Instant.now().toString()
        ));

        if (headerJson.length > 65535) throw new IOException("Header too large");

        ByteBuffer buf = ByteBuffer.allocate(FIXED_HEADER_LEN + headerJson.length).order(ByteOrder.BIG_ENDIAN);
        buf.put(MAGIC);
        buf.put((byte)1);           // version
        buf.put(flags);
        buf.putShort((short)headerJson.length);
        buf.put(headerJson);
        buf.flip();

        ch.position(0);
        while (buf.hasRemaining()) ch.write(buf);
        ch.force(true);
    }

    private void validateHeaderAndRecover() throws IOException {
        ch.position(0);
        ByteBuffer fixed = ByteBuffer.allocate(FIXED_HEADER_LEN).order(ByteOrder.BIG_ENDIAN);
        readFully(fixed);
        fixed.flip();

        byte[] magic = new byte[4];
        fixed.get(magic);
        if (!(magic[0]=='V' && magic[1]=='L' && magic[2]=='O' && magic[3]=='G'))
            throw new IOException("Bad magic");

        byte ver = fixed.get();
        if (ver != 1) throw new IOException("Unsupported version: " + ver);

        /* flags */ fixed.get();
        int headerLen = fixed.getShort() & 0xFFFF;

        ByteBuffer hdr = ByteBuffer.allocate(headerLen);
        readFully(hdr);

        // Recovery: truncate any partial frame at end
        truncateToLastFullFrame();
    }

    private void truncateToLastFullFrame() throws IOException {
        long size = ch.size();
        long pos = FIXED_HEADER_LEN;

        // read headerLen to jump correctly
        ch.position(4 + 1 + 1);
        ByteBuffer hb = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN);
        readFully(hb); hb.flip();
        int headerLen = hb.getShort() & 0xFFFF;
        pos = FIXED_HEADER_LEN + headerLen;

        long lastGood = pos;
        ch.position(pos);

        ByteBuffer lenBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);

        while (true) {
            lenBuf.clear();
            int r = ch.read(lenBuf);
            if (r == -1) break;
            if (r < 4) break; // partial length
            lenBuf.flip();
            int payloadLen = lenBuf.getInt();
            if (payloadLen <= 0 || payloadLen > 64 * 1024 * 1024) break; // sanity limit 64MiB
            long frameEnd = ch.position() + payloadLen;
            if (frameEnd > size) break; // partial payload
            // skip payload
            ch.position(frameEnd);
            lastGood = frameEnd;
        }

        if (lastGood != size) {
            ch.truncate(lastGood);
            ch.force(true);
        }
    }

    private long scanNextSeq() throws IOException {
        // Simple scan: read frames, track max seq, return max+1
        long pos;

        ch.position(4 + 1 + 1);
        ByteBuffer hb = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN);
        readFully(hb); hb.flip();
        int headerLen = hb.getShort() & 0xFFFF;
        pos = FIXED_HEADER_LEN + headerLen;

        long maxSeq = 0;
        ch.position(pos);

        ByteBuffer lenBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        ByteBuffer headBuf = ByteBuffer.allocate(1 + 8).order(ByteOrder.BIG_ENDIAN);

        while (true) {
            lenBuf.clear();
            int r = ch.read(lenBuf);
            if (r == -1) break;
            if (r < 4) break;
            lenBuf.flip();
            int payloadLen = lenBuf.getInt();

            headBuf.clear();
            readFully(headBuf);
            headBuf.flip();
            /* type */ headBuf.get();
            long seq = headBuf.getLong();
            if (seq > maxSeq) maxSeq = seq;

            // skip nonce + ct
            long skip = payloadLen - (1 + 8);
            ch.position(ch.position() + skip);
        }
        return maxSeq + 1;
    }

    private byte[] buildAad(byte type, long seq) {
        // aad = prefix || 0x00 || uint64_be(seq) || 0x00 || type
        ByteBuffer bb = ByteBuffer.allocate(aadPrefix.length + 1 + 8 + 1 + 1).order(ByteOrder.BIG_ENDIAN);
        bb.put(aadPrefix);
        bb.put((byte)0x00);
        bb.putLong(seq);
        bb.put((byte)0x00);
        bb.put(type);
        return bb.array();
    }

    private void readFully(ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            int r = ch.read(buf);
            if (r == -1) throw new EOFException();
        }
    }
}