package io.github.em.verilog.logger;

import java.nio.file.Path;
import java.util.Objects;

public final class VeriLoggerConfig {

    public enum Level { DEBUG, INFO, WARN, ERROR }

    public enum BackpressureMode {
        BLOCK,          // wait up to timeout
        DROP            // drop when full
    }

    public enum FaultMode {
        FAIL_FAST,      // log() throws once faulted
        DROP_ON_FAULT   // log() silently drops (but counts)
    }

    public Path logDir = Path.of("./logs");
    public String filePrefix = "app";
    public String currentFileName = "current.vlog";

    public String aadPrefix = "VeriLog|v1";

    /** 32 bytes DEK for XChaCha20-Poly1305 */
    public byte[] encryptionKey32;

    public int queueCapacity = 50_000;

    public BackpressureMode backpressureMode = BackpressureMode.BLOCK;
    public long offerTimeoutMs = 50; // for BLOCK mode

    public FaultMode faultMode = FaultMode.DROP_ON_FAULT;

    /** rotate when current file exceeds this many bytes */
    public long rotateBytes = 100L * 1024 * 1024;

    /** flush policy */
    public int flushEveryN = 500;
    public long flushEveryMs = 1000;
    public boolean fsyncOnFlush = false;

    public String actor = "app";
    public io.github.em.verilog.sign.LogSigner signer;

    /** If DROP: never drop WARN/ERROR (will block briefly instead) */
    public boolean preferReliabilityForWarnError = true;

    public boolean rotateOnStartup = true;

    public void validate() {
        Objects.requireNonNull(logDir, "logDir");
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(signer, "signer");
        if (filePrefix == null || filePrefix.isBlank()) throw new IllegalArgumentException("filePrefix");
        if (currentFileName == null || currentFileName.isBlank()) throw new IllegalArgumentException("currentFileName");
        if (encryptionKey32 == null || encryptionKey32.length != 32)
            throw new IllegalArgumentException("encryptionKey32 must be 32 bytes");
        if (queueCapacity < 1) throw new IllegalArgumentException("queueCapacity");
        if (offerTimeoutMs < 0) throw new IllegalArgumentException("offerTimeoutMs");
        if (rotateBytes < 1024 * 1024) throw new IllegalArgumentException("rotateBytes too small");
        if (flushEveryN < 1) throw new IllegalArgumentException("flushEveryN");
        if (flushEveryMs < 1) throw new IllegalArgumentException("flushEveryMs");
    }
}