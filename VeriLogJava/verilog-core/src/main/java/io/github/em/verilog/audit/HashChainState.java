/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
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