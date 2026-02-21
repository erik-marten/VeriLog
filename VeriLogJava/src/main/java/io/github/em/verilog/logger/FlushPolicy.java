/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
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