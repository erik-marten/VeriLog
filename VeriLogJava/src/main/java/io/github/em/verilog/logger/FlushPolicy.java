package io.github.em.verilog.logger;

final class FlushPolicy {
    final int flushEveryN;
    final long flushEveryMs;
    final boolean fsyncOnFlush;

    FlushPolicy(int flushEveryN, long flushEveryMs, boolean fsyncOnFlush) {
        this.flushEveryN = flushEveryN;
        this.flushEveryMs = flushEveryMs;
        this.fsyncOnFlush = fsyncOnFlush;
    }
}