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

import java.util.concurrent.atomic.AtomicLong;

public final class LoggerMetrics {
    private final AtomicLong dropped = new AtomicLong(0);
    private final AtomicLong written = new AtomicLong(0);

    void incDropped() { dropped.incrementAndGet(); }
    void incWritten() { written.incrementAndGet(); }

    public long droppedCount() { return dropped.get(); }
    public long writtenCount() { return written.get(); }
}