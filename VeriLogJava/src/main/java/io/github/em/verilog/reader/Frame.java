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