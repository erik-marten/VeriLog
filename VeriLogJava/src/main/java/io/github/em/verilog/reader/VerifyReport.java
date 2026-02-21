/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
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