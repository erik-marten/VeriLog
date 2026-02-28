package io.github.em.verilog.logger;

import io.github.em.verilog.logger.utils.TestConfigBuilder;
import io.github.em.verilog.sign.LogSigner;
import org.junit.jupiter.api.Test;

import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class VeriLoggerTest {

    @Test
    void should_write_events_when_logging_and_should_not_throw_when_logging_after_close() throws Exception {
        Path dir = Files.createTempDirectory("verilog-logger-test");

        VeriLoggerConfig cfg =
                TestConfigBuilder.configBuilder(dir)
                        .queueCapacity(1) // flush frequently for tests
                        .flushEveryMs(10)
                        .rotateOnStartup(true)
                        .build();

        try (VeriLogger logger = VeriLogger.create(cfg)) {
            for (int i = 0; i < 50; i++) {
                logger.info("hello-" + i);
            }

            // Give writer a moment to drain queue
            waitUntil(() -> logger.writtenCount() >= 1, Duration.ofSeconds(2));

            assertTrue(logger.writtenCount() >= 1);
            assertEquals(0, logger.droppedCount());
        }

        // After close, log() is a no-op (should not throw)
        try (VeriLogger logger2 = VeriLogger.create(cfg)) {
            logger2.close();
            logger2.info("should-not-throw");
            // no assertion needed; success = no exception
        }
    }

    @Test
    void should_drop_some_events_when_queue_capacity_is_small_and_mode_is_drop_under_high_load() throws Exception {
        Path dir = Files.createTempDirectory("verilog-logger-drop");

        VeriLoggerConfig cfg = TestConfigBuilder.configBuilder(dir)
                .backpressureMode(VeriLoggerConfig.BackpressureMode.DROP)
                .offerTimeoutMs(0)
                .queueCapacity(1)
                .flushEveryN(1000)
                .flushEveryMs(1000)
                .build();
        try (VeriLogger logger = VeriLogger.create(cfg)) {
            // Burst a lot of events quickly
            for (int i = 0; i < 50_000; i++) {
                logger.log(VeriLoggerConfig.Level.INFO, "msg", Map.of("i", i));
            }

            // expect at least some drops with queueCapacity=1 + DROP mode
            waitUntil(() -> logger.droppedCount() > 0, Duration.ofSeconds(2));
            assertTrue(logger.droppedCount() > 0);
        }
    }

    @Test
    void should_rotate_existing_current_file_when_rotate_on_startup_is_enabled_and_current_is_non_empty() throws Exception {
        Path dir = Files.createTempDirectory("verilog-logger-rotate");
        Path current = dir.resolve("current.vlog");

        // create a non-empty "current.vlog"
        Files.write(current, new byte[]{1, 2, 3}, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        VeriLoggerConfig cfg = TestConfigBuilder.configBuilder(dir)
                .currentFileName("current.vlog")
                .rotateOnStartup(true)
                .flushEveryMs(10)
                .flushEveryN(10)
                .build();


        try (VeriLogger logger = VeriLogger.create(cfg)) {
            logger.info("post-rotate");
            waitUntil(() -> logger.writtenCount() >= 1, Duration.ofSeconds(2));
        }

        // rotated file should exist (prefix + timestamp)
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, cfg.getFilePrefix() + "-*.vlog")) {
            boolean found = false;
            for (Path p : ds) {
                found = true;
            }
            assertTrue(found, "Expected a rotated file in logDir");
        }

        assertTrue(Files.exists(current), "Expected current.vlog to exist after startup rotation");
    }

    @Test
    void should_throw_illegal_state_when_writer_faults_and_fault_mode_is_fail_fast() throws Exception {
        Path dir = Files.createTempDirectory("verilog-logger-fault");

        VeriLoggerConfig cfg = TestConfigBuilder.configBuilder(dir)
                .faultMode(VeriLoggerConfig.FaultMode.FAIL_FAST)
                .signer(new ThrowingSigner())// writer will fault when it tries to sign
                .queueCapacity(64)
                .flushEveryN(1)
                .flushEveryMs(10)
                .build();

        try (VeriLogger logger = VeriLogger.create(cfg)) {
            // enqueue something that will fault the writer when processed
            logger.info("this-will-fault");

            // Wait until the logger becomes faulted (observed by log() throwing)
            waitUntil(() -> {
                try {
                    logger.info("probe");
                    return false;
                } catch (IllegalStateException expected) {
                    return true;
                }
            }, Duration.ofSeconds(3));

            assertThrows(IllegalStateException.class, () -> logger.info("should-throw-now"));
        }
    }

    // -------- helpers --------

//    private static VeriLoggerConfig.Builder baseCfg(Path dir) throws Exception {
//        byte[] dek = new byte[32];
//        new SecureRandom().nextBytes(dek);
//
//        VeriLoggerConfig cfg = TestConfigBuilder.configBuilder(dir)
//                .filePrefix("app")
//                .currentFileName("current.vlog")
//                .actor("test")
//                .encryptionKey(dek)
//                .signer(new TestSigner());
//        return cfg;
//    }

    private static void waitUntil(BooleanSupplier condition, Duration timeout) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while (System.currentTimeMillis() < deadline) {
            if (condition.getAsBoolean()) return;
        }
        fail("Condition not met within " + timeout);
    }

    @FunctionalInterface
    private interface BooleanSupplier {
        boolean getAsBoolean();
    }

    private static final class TestSigner implements LogSigner {
        @Override
        public String keyId() {
            return "test-key";
        }

        @Override
        public byte[] signEntryHash(byte[] entryHash32) {
            // produce deterministic 64 bytes (NOT a real signature- sufficient for writer path)
            byte[] out = new byte[64];
            for (int i = 0; i < out.length; i++) {
                out[i] = entryHash32[i % entryHash32.length];
            }
            return out;
        }
    }

    private static final class ThrowingSigner implements LogSigner {
        @Override
        public String keyId() {
            return "throwing-key";
        }

        @Override
        public byte[] signEntryHash(byte[] entryHash32) {
            throw new RuntimeException("boom");
        }
    }
}