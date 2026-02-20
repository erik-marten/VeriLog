package io.github.em.verilog.reader;

public final class VerifyReport {
    public final boolean ok;
    public final long seq;       // seq where it failed (or last verified)
    public final String reason;  // null if ok

    private VerifyReport(boolean ok, long seq, String reason) {
        this.ok = ok;
        this.seq = seq;
        this.reason = reason;
    }

    public static VerifyReport ok(long lastSeq) {
        return new VerifyReport(true, lastSeq, null);
    }

    public static VerifyReport fail(long seq, String reason) {
        return new VerifyReport(false, seq, reason);
    }
}