package io.github.em.verilog.audit;

public final class HashChainState {
    private long nextSeq;
    private String prevHashHex; // 64 hex chars

    public HashChainState(long nextSeq, String prevHashHex) {
        this.nextSeq = nextSeq;
        this.prevHashHex = prevHashHex;
    }

    public long nextSeq() { return nextSeq; }
    public String prevHashHex() { return prevHashHex; }

    public long allocateSeq() { return nextSeq++; }

    public void updatePrevHash(String entryHashHex) {
        this.prevHashHex = entryHashHex;
    }

    public static HashChainState fresh() {
        return new HashChainState(1, "0".repeat(64));
    }
}