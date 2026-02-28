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

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

final class BackpressureEnqueuer {

    private final VeriLoggerConfig cfg;
    private final BlockingQueue<LogEvent> queue;

    BackpressureEnqueuer(VeriLoggerConfig cfg, BlockingQueue<LogEvent> queue) {
        this.cfg = cfg;
        this.queue = queue;
    }

    boolean enqueue(LogEvent ev) {
        try {
            long timeoutMs = cfg.getOfferTimeoutMs();
            boolean mustWait =
                    cfg.getBackpressureMode() != VeriLoggerConfig.BackpressureMode.DROP ||
                            (cfg.isPreferReliabilityForWarnError() &&
                                    (ev.level == VeriLoggerConfig.Level.WARN || ev.level == VeriLoggerConfig.Level.ERROR));

            return mustWait
                    ? queue.offer(ev, timeoutMs, TimeUnit.MILLISECONDS)
                    : queue.offer(ev);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}