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