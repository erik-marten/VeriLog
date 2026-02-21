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
            if (cfg.backpressureMode == VeriLoggerConfig.BackpressureMode.DROP) {
                if (cfg.preferReliabilityForWarnError &&
                        (ev.level == VeriLoggerConfig.Level.WARN || ev.level == VeriLoggerConfig.Level.ERROR)) {
                    return queue.offer(ev, cfg.offerTimeoutMs, TimeUnit.MILLISECONDS);
                }
                return queue.offer(ev);
            } else {
                return queue.offer(ev, cfg.offerTimeoutMs, TimeUnit.MILLISECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}