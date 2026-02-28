package io.github.em.verilog.logger;

import io.github.em.verilog.sign.LogSigner;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class BackpressureEnqueuerTest {

    LogSigner dummySigner = mock(LogSigner.class);

    @Test
    void should_drop_event_when_queue_is_full_and_mode_is_drop_and_level_is_info() {
        VeriLoggerConfig cfg = new VeriLoggerConfig.Builder()
                .backpressureMode(VeriLoggerConfig.BackpressureMode.DROP)
                .preferReliabilityForWarnError(true)
                .signer(dummySigner)
                .build(); // doesn’t matter for INFO

        BlockingQueue<LogEvent> q = new ArrayBlockingQueue<>(1);
        BackpressureEnqueuer enq = new BackpressureEnqueuer(cfg, q);

        assertTrue(enq.enqueue(ev(VeriLoggerConfig.Level.INFO)));
        assertFalse(enq.enqueue(ev(VeriLoggerConfig.Level.INFO))); // full => drop
    }

    @Test
    void should_wait_and_enqueue_when_queue_is_full_and_mode_is_drop_and_level_is_warn_and_prefer_reliability_is_true() throws Exception {
        VeriLoggerConfig cfg = new VeriLoggerConfig.Builder()
                .backpressureMode(VeriLoggerConfig.BackpressureMode.BLOCK)
                .preferReliabilityForWarnError(true)
                .offerTimeoutMs(250)
                .signer(dummySigner)
                .build();
        BlockingQueue<LogEvent> q = new ArrayBlockingQueue<>(1);
        BackpressureEnqueuer enq = new BackpressureEnqueuer(cfg, q);

        // Fill queue
        assertTrue(enq.enqueue(ev(VeriLoggerConfig.Level.INFO)));

        CountDownLatch startedBlocking = new CountDownLatch(1);

        Thread enqueuerThread = new Thread(() -> {
            startedBlocking.countDown();
            enq.enqueue(ev(VeriLoggerConfig.Level.WARN));
        });

        enqueuerThread.start();

        // Wait until enqueue attempt started
        startedBlocking.await();

        // Now free space deterministically
        q.take();

        enqueuerThread.join();

        assertEquals(1, q.size());
    }

    @Test
    void should_timeout_and_return_false_when_queue_is_full_and_mode_is_block() {
        LogSigner dummySigner = mock(LogSigner.class);
        VeriLoggerConfig cfg = new VeriLoggerConfig.Builder()
                .backpressureMode(VeriLoggerConfig.BackpressureMode.BLOCK)
                .offerTimeoutMs(200)
                .signer(dummySigner)
                .build();

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