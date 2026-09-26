package io.github.em.verilog.logback;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy;
import ch.qos.logback.core.util.FileSize;
import io.github.em.verilog.EcdsaSigCodec;
import io.github.em.verilog.audit.HashChainState;
import io.github.em.verilog.reader.FramedFileReader;
import io.github.em.verilog.reader.MapPublicKeyResolver;
import io.github.em.verilog.reader.VeriLogReader;
import io.github.em.verilog.sign.LogSigner;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.event.KeyValuePair;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

class VeriLogRollingFileAppenderTest {
    @TempDir Path tempDir;
    private final Material material = new Material();
    private final VeriLogReader reader = new VeriLogReader();

    @Test
    void fresh_directory_first_event_and_restart_continue_chain() throws Exception {
        Path dir = tempDir.resolve("missing").resolve("nested");
        Path active = dir.resolve("audit.vlog");
        VeriLogRollingFileAppender first = appender(active, 10_000);
        first.start();
        assertTrue(first.isStarted());
        assertTrue(Files.isDirectory(dir));
        assertEquals(1, headerCount(active));
        first.doAppend(event());
        first.stop();
        assertEquals(2, recover(dir, active).nextSeq());

        VeriLogRollingFileAppender second = appender(active, 10_000);
        second.start();
        assertTrue(second.isStarted());
        second.doAppend(event());
        second.stop();
        assertEquals(3, recover(dir, active).nextSeq());
        assertEquals(1, headerCount(active));
        assertFalse(first.isStarted());
        first.start();
        assertFalse(first.isStarted(), "a stopped instance cannot reuse stale state");
        assertThrows(IllegalStateException.class, () -> first.setActor("changed"));
        assertThrows(IllegalStateException.class, () -> first.setAppend(false));
    }

    @Test
    void header_only_active_resumes_and_zero_byte_active_is_new() throws Exception {
        Path active = tempDir.resolve("audit.vlog");
        VeriLogRollingFileAppender initial = appender(active, 10_000);
        initial.start();
        initial.stop();
        byte[] original = Files.readAllBytes(active);

        VeriLogRollingFileAppender resume = appender(active, 10_000);
        resume.start();
        resume.doAppend(event());
        resume.stop();
        assertArrayEquals(original, java.util.Arrays.copyOf(Files.readAllBytes(active), original.length));
        assertEquals(1, headerCount(active));
        assertEquals(2, recover(tempDir, active).nextSeq());

        Files.delete(active);
        Files.createFile(active);
        VeriLogRollingFileAppender zero = appender(active, 10_000);
        zero.start();
        assertTrue(zero.isStarted());
        zero.stop();
        assertEquals(1, headerCount(active));
    }

    @Test
    void missing_active_with_rotated_history_recovers_and_writes_new_header() throws Exception {
        Path active = tempDir.resolve("audit.vlog");
        VeriLogRollingFileAppender first = appender(active, 10_000);
        first.start();
        first.doAppend(event());
        first.stop();
        Files.move(active, tempDir.resolve("older.vlog"));

        VeriLogRollingFileAppender second = appender(active, 10_000);
        second.setAadPrefix("other");
        second.start();
        assertTrue(second.isStarted());
        second.doAppend(event());
        second.stop();
        assertEquals(1, headerCount(active));
        assertEquals("other", reader.readAadPrefix(active));
        assertEquals(3, recover(tempDir, active).nextSeq());
        assertTrue(reader.verifyDirectory(tempDir, material.dek, material.resolver).allOk());
    }

    @Test
    void partial_tail_is_verified_then_physically_removed_and_sequence_reused() throws Exception {
        Path active = tempDir.resolve("audit.vlog");
        VeriLogRollingFileAppender first = appender(active, 10_000);
        first.start();
        first.doAppend(event());
        first.stop();
        long completeLength = Files.size(active);
        byte[] interrupted = ByteBuffer.allocate(4 + 5).putInt(100).put(new byte[5]).array();
        Files.write(active, interrupted, StandardOpenOption.APPEND);
        assertEquals(2, recover(tempDir, active).nextSeq());

        VeriLogRollingFileAppender second = appender(active, 10_000);
        second.start();
        assertTrue(second.isStarted());
        assertEquals(completeLength, Files.size(active), "repair occurs before Logback appends");
        second.doAppend(event());
        second.stop();
        assertEquals(3, recover(tempDir, active).nextSeq());
        assertTrue(reader.verifyDirectory(tempDir, material.dek, material.resolver).allOk());
    }

    @Test
    void resume_rejects_mismatched_aad_without_opening_or_modifying_active_file() throws Exception {
        Path active = tempDir.resolve("audit.vlog");
        VeriLogRollingFileAppender first = appender(active, 10_000);
        first.start();
        first.doAppend(event());
        first.stop();
        byte[] before = Files.readAllBytes(active);

        VeriLogRollingFileAppender mismatched = appender(active, 10_000);
        mismatched.setAadPrefix("other");
        mismatched.start();
        assertFalse(mismatched.isStarted());
        assertNull(mismatched.getOutputStream());
        mismatched.doAppend(event());
        assertArrayEquals(before, Files.readAllBytes(active));
        assertEquals(1, headerCount(active));
        assertEquals(2, recover(tempDir, active).nextSeq());
        assertTrue(mismatched.getContext().getStatusManager().getCopyOfStatusList().stream()
                .anyMatch(status -> status.getMessage().contains("AAD prefix does not match existing VLOG header")));
    }

    @Test
    void mismatched_aad_does_not_truncate_a_partial_active_tail() throws Exception {
        Path active = tempDir.resolve("audit.vlog");
        VeriLogRollingFileAppender first = appender(active, 10_000);
        first.start();
        first.doAppend(event());
        first.stop();
        Files.write(active, ByteBuffer.allocate(9).putInt(100).put(new byte[5]).array(),
                StandardOpenOption.APPEND);
        byte[] before = Files.readAllBytes(active);

        VeriLogRollingFileAppender mismatched = appender(active, 10_000);
        mismatched.setAadPrefix("other");
        mismatched.start();
        assertFalse(mismatched.isStarted());
        assertNull(mismatched.getOutputStream());
        assertArrayEquals(before, Files.readAllBytes(active));
        assertEquals(2, recover(tempDir, active).nextSeq());
    }

    @Test
    void tampered_complete_frame_fails_without_changing_any_byte() throws Exception {
        Path active = tempDir.resolve("audit.vlog");
        VeriLogRollingFileAppender first = appender(active, 10_000);
        first.start();
        first.doAppend(event());
        first.stop();
        byte[] tampered = Files.readAllBytes(active);
        tampered[tampered.length - 3] ^= 1;
        Files.write(active, tampered);

        VeriLogRollingFileAppender second = appender(active, 10_000);
        second.start();
        assertFalse(second.isStarted());
        assertArrayEquals(tampered, Files.readAllBytes(active));
    }

    @Test
    void only_designated_active_file_can_tolerate_a_partial_tail() throws Exception {
        Path previousActive = tempDir.resolve("current.vlog");
        VeriLogRollingFileAppender first = appender(previousActive, 10_000);
        first.start();
        first.doAppend(event());
        first.stop();
        Files.write(previousActive, new byte[]{1, 2}, StandardOpenOption.APPEND);
        byte[] before = Files.readAllBytes(previousActive);

        VeriLogRollingFileAppender second = appender(tempDir.resolve("audit.vlog"), 10_000);
        second.start();
        assertFalse(second.isStarted());
        assertArrayEquals(before, Files.readAllBytes(previousActive));
    }

    @Test
    void missing_security_configuration_is_rejected_before_file_creation() throws Exception {
        Path active = tempDir.resolve("audit.vlog");
        VeriLogRollingFileAppender appender = appender(active, 10_000);
        appender.setActor(" ");
        appender.setSigner(null);
        appender.setPublicKeyResolver(null);
        appender.setDek32(new byte[31]);
        appender.setAadPrefix(null);
        appender.start();
        assertFalse(appender.isStarted());
        assertFalse(Files.exists(active));
    }

    @Test
    void rejects_zero_byte_rotated_file_and_unsafe_modes_and_compression() throws Exception {
        Path active = tempDir.resolve("audit.vlog");
        Files.createFile(tempDir.resolve("older.vlog"));
        VeriLogRollingFileAppender rotated = appender(active, 10_000);
        rotated.start();
        assertFalse(rotated.isStarted());
        Files.delete(tempDir.resolve("older.vlog"));

        VeriLogRollingFileAppender noAppend = appender(active, 10_000);
        noAppend.setAppend(false);
        noAppend.start();
        assertFalse(noAppend.isStarted());
        VeriLogRollingFileAppender prudent = appender(active, 10_000);
        prudent.setPrudent(true);
        prudent.start();
        assertFalse(prudent.isStarted());

        Files.write(tempDir.resolve("old.vlog.gz"), new byte[]{1});
        VeriLogRollingFileAppender compressed = appender(active, 10_000);
        compressed.start();
        assertFalse(compressed.isStarted());
        assertTrue(compressed.getContext().getStatusManager().getCopyOfStatusList().stream()
                .anyMatch(s -> s.getMessage().contains("Compressed VeriLog archive")));
    }

    @Test
    void real_rollover_writes_one_header_per_file_and_preserves_chain() throws Exception {
        Path active = tempDir.resolve("audit.vlog");
        VeriLogRollingFileAppender appender = appender(active, 700);
        appender.start();
        assertTrue(appender.isStarted());
        for (int i = 0; i < 12; i++) appender.doAppend(event());
        appender.stop();
        List<Path> files = vlogFiles();
        assertTrue(files.size() > 1, "real Logback rolling policy should create archives");
        for (Path file : files) assertEquals(1, headerCount(file), file.toString());
        assertTrue(reader.verifyDirectory(tempDir, material.dek, material.resolver).allOk());
        assertEquals(13, recover(tempDir, active).nextSeq());
    }

    @Test
    void concurrent_writes_remain_contiguous_through_real_rollover() throws Exception {
        Path active = tempDir.resolve("audit.vlog");
        VeriLogRollingFileAppender appender = appender(active, 2_000);
        appender.start();
        int workers = 4, perWorker = 12;
        CountDownLatch ready = new CountDownLatch(1);
        var pool = Executors.newFixedThreadPool(workers);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int worker = 0; worker < workers; worker++) {
                futures.add(pool.submit(() -> {
                    ready.await();
                    for (int i = 0; i < perWorker; i++) appender.doAppend(event());
                    return null;
                }));
            }
            ready.countDown();
            for (Future<?> future : futures) future.get();
        } finally {
            pool.shutdownNow();
            appender.stop();
        }
        assertTrue(vlogFiles().size() > 1);
        assertTrue(reader.verifyDirectory(tempDir, material.dek, material.resolver).allOk());
        assertEquals(workers * perWorker + 1, recover(tempDir, active).nextSeq());
    }

    private VeriLogRollingFileAppender appender(Path active, long maxBytes) {
        LoggerContext context = new LoggerContext();
        VeriLogRollingFileAppender appender = new VeriLogRollingFileAppender();
        appender.setContext(context);
        appender.setName("audit");
        appender.setActor("test-actor");
        appender.setSigner(material.signer);
        appender.setPublicKeyResolver(material.resolver);
        appender.setDek32(material.dek);
        appender.setAadPrefix("VeriLog|v1");
        appender.setFile(active.toString());
        SizeAndTimeBasedRollingPolicy<ch.qos.logback.classic.spi.ILoggingEvent> policy =
                new SizeAndTimeBasedRollingPolicy<>();
        policy.setContext(context);
        policy.setParent(appender);
        policy.setFileNamePattern(active.getParent().resolve("archive.%d{yyyy-MM-dd}.%i.vlog").toString());
        policy.setMaxFileSize(new FileSize(maxBytes));
        policy.start();
        appender.setRollingPolicy(policy);
        return appender;
    }

    private HashChainState recover(Path directory, Path active) throws Exception {
        return reader.recoverChainState(directory, active, material.dek, material.resolver);
    }

    private List<Path> vlogFiles() throws Exception {
        try (var files = Files.list(tempDir)) {
            return files.filter(p -> p.getFileName().toString().endsWith(".vlog"))
                    .collect(java.util.stream.Collectors.toList());
        }
    }

    private static int headerCount(Path file) throws Exception {
        try (FramedFileReader frames = new FramedFileReader(file)) {
            frames.positionAtFirstFrame();
            int count = 1;
            while (frames.readNextFrame(false) != null) { /* structural scan */ }
            return count;
        }
    }

    private static LoggingEvent event() {
        LoggingEvent event = new LoggingEvent();
        event.setInstant(Instant.now());
        event.setLevel(Level.INFO);
        event.setLoggerName("audit.test");
        event.setThreadName(Thread.currentThread().getName());
        event.setMessage("audit event");
        event.setMDCPropertyMap(Map.of());
        event.addKeyValuePair(new KeyValuePair("verilog.eventType", "test.event"));
        return event;
    }

    private static final class Material {
        final byte[] dek = new byte[32];
        final LogSigner signer;
        final MapPublicKeyResolver resolver;

        Material() {
            new SecureRandom().nextBytes(dek);
            var x9 = NISTNamedCurves.getByName("P-256");
            var domain = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
            var generator = new ECKeyPairGenerator();
            generator.init(new ECKeyGenerationParameters(domain, new SecureRandom()));
            AsymmetricCipherKeyPair pair = generator.generateKeyPair();
            var privateKey = (ECPrivateKeyParameters) pair.getPrivate();
            var publicKey = (ECPublicKeyParameters) pair.getPublic();
            resolver = new MapPublicKeyResolver(Map.of("test-key", publicKey));
            signer = new LogSigner() {
                @Override public String keyId() { return "test-key"; }
                @Override public byte[] signEntryHash(byte[] hash) {
                    var ecdsa = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
                    ecdsa.init(true, privateKey);
                    try {
                        var parts = ecdsa.generateSignature(io.github.em.verilog.CryptoUtil.sha256(hash));
                        return EcdsaSigCodec.derToRaw(StandardDSAEncoding.INSTANCE.encode(domain.getN(), parts[0], parts[1]));
                    } catch (Exception e) { throw new IllegalStateException(e); }
                }
            };
        }
    }
}
