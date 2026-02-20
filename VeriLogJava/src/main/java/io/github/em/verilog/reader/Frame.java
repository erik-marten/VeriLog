package io.github.em.verilog.reader;

public final class Frame {
    public final byte type;
    public final long seq;
    public final byte[] nonce24;
    public final byte[] ct;

    public Frame(byte type, long seq, byte[] nonce24, byte[] ct) {
        this.type = type;
        this.seq = seq;
        this.nonce24 = nonce24;
        this.ct = ct;
    }
}