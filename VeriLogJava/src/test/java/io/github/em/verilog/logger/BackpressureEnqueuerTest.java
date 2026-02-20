package io.github.em.verilog.logger;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import static org.junit.jupiter.api.Assertions.*;

class BackpressureEnqueuerTest {

    @Test
    void should_drop_event_when_queue_is_full_and_mode_is_drop_and_level_is_info() {
        VeriLoggerConfig cfg = new VeriLoggerConfig();
        cfg.backpressureMode = VeriLoggerConfig.BackpressureMode.DROP;
        cfg.preferReliabilityForWarnError = true; // doesn’t matter for INFO

        BlockingQueue<LogEvent> q = new ArrayBlockingQueue<>(1);
        BackpressureEnqueuer enq = new BackpressureEnqueuer(cfg, q);

        assertTrue(enq.enqueue(ev(VeriLoggerConfig.Level.INFO)));
        assertFalse(enq.enqueue(ev(VeriLoggerConfig.Level.INFO))); // full => drop
    }

    @Test
    void should_wait_and_enqueue_when_queue_is_full_and_mode_is_drop_and_level_is_warn_and_prefer_reliability_is_true() throws Exception {
        VeriLoggerConfig cfg = new VeriLoggerConfig();
        cfg.backpressureMode = VeriLoggerConfig.BackpressureMode.DROP;
        cfg.preferReliabilityForWarnError = true;
        cfg.offerTimeoutMs = 250;

        BlockingQueue<LogEvent> q = new ArrayBlockingQueue<>(1);
        BackpressureEnqueuer enq = new BackpressureEnqueuer(cfg, q);

        // Fill queue
        assertTrue(enq.enqueue(ev(VeriLoggerConfig.Level.INFO)));

        // After a short delay, drain the queue to allow WARN to be enqueued via timed offer
        Thread drainer = new Thread(() -> {
            try {
                Thread.sleep(80);
                q.take();
            } catch (Exception ignored) {}
        });
        drainer.start();

        long t0 = System.currentTimeMillis();
        boolean ok = enq.enqueue(ev(VeriLoggerConfig.Level.WARN));
        long dt = System.currentTimeMillis() - t0;

        assertTrue(ok, "WARN should be enqueued using timed offer when preferReliabilityForWarnError=true");
        assertTrue(dt >= 50, "Should have waited (at least a bit) for space in the queue");
    }

    @Test
    void should_timeout_and_return_false_when_queue_is_full_and_mode_is_block() throws Exception {
        VeriLoggerConfig cfg = new VeriLoggerConfig();
        cfg.backpressureMode = VeriLoggerConfig.BackpressureMode.BLOCK;
        cfg.offerTimeoutMs = 200;

        BlockingQueue<LogEvent> q = new ArrayBlockingQueue<>(1);
        BackpressureEnqueuer enq = new BackpressureEnqueuer(cfg, q);

        assertTrue(enq.enqueue(ev(VeriLoggerConfig.Level.INFO)));

        long t0 = System.currentTimeMillis();
        boolean ok = enq.enqueue(ev(VeriLoggerConfig.Level.INFO)); // should time out (queue never drained)
        long dt = System.currentTimeMillis() - t0;

        assertFalse(ok);
        assertTrue(dt >= 150, "Should have waited close to offerTimeoutMs");
    }

    private static LogEvent ev(VeriLoggerConfig.Level level) {
        return new LogEvent(level, "msg", Map.of("k", "v"), Instant.now());
    }
}