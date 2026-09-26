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

import io.github.em.verilog.sign.LogSigner;

import java.nio.file.Path;
import java.util.Objects;

public final class VeriLoggerConfig {

    private Path logDir;
    private String filePrefix;
    private String currentFileName;
    private String aadPrefix;
    /**
     * 32 bytes DEK for XChaCha20-Poly1305
     */
    private  byte[] encryptionKey;
    private  int queueCapacity;
    private BackpressureMode backpressureMode;
    private long offerTimeoutMs; // for BLOCK mode
    private FaultMode faultMode;
    /**
     * rotate when current file exceeds this many bytes
     */
    private long rotateBytes = 0;

    /**
     * flush policy
     */
    private int flushEveryN;
    private long flushEveryMs;
    private boolean fsyncOnFlush;
    private String actor;
    private LogSigner signer;
    /**
     * If DROP: never drop WARN/ERROR (will block briefly instead)
     */
    private boolean preferReliabilityForWarnError;
    private boolean rotateOnStartup;
    private boolean installShutdownHook;
    private long shutdownTimeoutMs; // secure Default

    public enum BackpressureMode {
        BLOCK,          // wait up to timeout
        DROP            // drop when full
    }

    public enum Level {
        DEBUG,
        INFO,
        WARN,
        ERROR
    }

    public enum FaultMode {
        FAIL_FAST,      // log() throws once faulted
        DROP_ON_FAULT   // log() silently drops (but counts)
    }

    public Path getLogDir() {
        return logDir;
    }

    public String getFilePrefix() {
        return filePrefix;
    }

    public String getCurrentFileName() {
        return currentFileName;
    }

    public String getAadPrefix() {
        return aadPrefix;
    }

    public byte[] getEncryptionKey() {
        return encryptionKey.clone();
    }

    public int getQueueCapacity() {
        return queueCapacity;
    }

    public BackpressureMode getBackpressureMode() {
        return backpressureMode;
    }

    public long getOfferTimeoutMs() {
        return offerTimeoutMs;
    }

    public FaultMode getFaultMode() {
        return faultMode;
    }

    public long getRotateBytes() {
        return rotateBytes;
    }

    public int getFlushEveryN() {
        return flushEveryN;
    }

    public long getFlushEveryMs() {
        return flushEveryMs;
    }

    public boolean isFsyncOnFlush() {
        return fsyncOnFlush;
    }

    public String getActor() {
        return actor;
    }

    public LogSigner getSigner() {
        return signer;
    }

    public boolean isPreferReliabilityForWarnError() {
        return preferReliabilityForWarnError;
    }

    public boolean isRotateOnStartup() {
        return rotateOnStartup;
    }

    public boolean isInstallShutdownHook() {
        return installShutdownHook;
    }

    public long getShutdownTimeoutMs() {
        return shutdownTimeoutMs;
    }

    VeriLoggerConfig(Builder b) {
        this.logDir = b.logDir;
        this.filePrefix = b.filePrefix;
        this.currentFileName = b.currentFileName;
        this.aadPrefix = b.aadPrefix;
        this.encryptionKey = b.encryptionKey == null ? null : b.encryptionKey.clone(); // important
        this.queueCapacity = b.queueCapacity;
        this.backpressureMode = b.backpressureMode;
        this.offerTimeoutMs = b.offerTimeoutMs;
        this.faultMode = b.faultMode;
        this.rotateBytes = b.rotateBytes;
        this.flushEveryN = b.flushEveryN;
        this.flushEveryMs = b.flushEveryMs;
        this.fsyncOnFlush = b.fsyncOnFlush;
        this.actor = b.actor;
        this.signer = b.signer;
        this.preferReliabilityForWarnError = b.preferReliabilityForWarnError;
        this.rotateOnStartup = b.rotateOnStartup;
        this.installShutdownHook = b.installShutdownHook;
        this.shutdownTimeoutMs = b.shutdownTimeoutMs;

        validate();
    }

    public void validate() {
        Objects.requireNonNull(logDir, "logDir");
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(signer, "signer");
        if (filePrefix == null || filePrefix.isBlank()) throw new IllegalArgumentException("filePrefix");
        if (currentFileName == null || currentFileName.isBlank()) throw new IllegalArgumentException("currentFileName");
        if (encryptionKey == null || encryptionKey.length != 32)
            throw new IllegalArgumentException("encryptionKey32 must be 32 bytes");
        if (queueCapacity < 1) throw new IllegalArgumentException("queueCapacity");
        if (offerTimeoutMs < 0) throw new IllegalArgumentException("offerTimeoutMs");
        if (rotateBytes < 1024 * 1024) throw new IllegalArgumentException("rotateBytes too small");
        if (flushEveryN < 1) throw new IllegalArgumentException("flushEveryN");
        if (flushEveryMs < 1) throw new IllegalArgumentException("flushEveryMs");
    }

    public static class Builder {
        private Path logDir = Path.of("./logs");
        private String filePrefix = "app";
        private String currentFileName = "current.vlog";
        private String aadPrefix = "VeriLog|v1";
        private byte[] encryptionKey = new byte[32];
        private int queueCapacity = 50_000;
        private BackpressureMode backpressureMode = BackpressureMode.BLOCK;
        private long offerTimeoutMs = 50;
        private FaultMode faultMode = FaultMode.DROP_ON_FAULT;
        private long rotateBytes = 100L * 1024 * 1024;
        private int flushEveryN = 500;
        private long flushEveryMs = 1000;
        private boolean fsyncOnFlush = false;
        private String actor = "app";
        private LogSigner signer;
        private boolean preferReliabilityForWarnError = true;
        private boolean rotateOnStartup = true;
        private boolean installShutdownHook = true;
        private long shutdownTimeoutMs = 5000;

        public Builder logDir(Path logDir) {
            this.logDir = logDir;
            return this;
        }

        public Builder filePrefix(String filePrefix) {
            this.filePrefix = filePrefix;
            return this;
        }

        public Builder currentFileName(String currentFileName) {
            this.currentFileName = currentFileName;
            return this;
        }

        public Builder aadPrefix(String aadPrefix) {
            this.aadPrefix = aadPrefix;
            return this;
        }

        public Builder encryptionKey(byte[] encryptionKey) {
            this.encryptionKey = encryptionKey.clone();
            return this;
        }

        public Builder queueCapacity(int queueCapacity) {
            this.queueCapacity = queueCapacity;
            return this;
        }

        public Builder backpressureMode(BackpressureMode backpressureMode) {
            this.backpressureMode = backpressureMode;
            return this;
        }

        public Builder offerTimeoutMs(long offerTimeoutMs) {
            this.offerTimeoutMs = offerTimeoutMs;
            return this;
        }

        public Builder faultMode(FaultMode faultMode) {
            this.faultMode = faultMode;
            return this;
        }

        public Builder rotateBytes(long rotateBytes) {
            this.rotateBytes = rotateBytes;
            return this;
        }

        public Builder flushEveryN(int flushEveryN) {
            this.flushEveryN = flushEveryN;
            return this;
        }

        public Builder flushEveryMs(long flushEveryMs) {
            this.flushEveryMs = flushEveryMs;
            return this;
        }

        public Builder fsyncOnFlush(boolean fsyncOnFlush) {
            this.fsyncOnFlush = fsyncOnFlush;
            return this;
        }

        public Builder actor(String actor) {
            this.actor = actor;
            return this;
        }

        public Builder signer(LogSigner signer) {
            this.signer = signer;
            return this;
        }

        public Builder preferReliabilityForWarnError(boolean preferReliabilityForWarnError) {
            this.preferReliabilityForWarnError = preferReliabilityForWarnError;
            return this;
        }

        public Builder rotateOnStartup(boolean rotateOnStartup) {
            this.rotateOnStartup = rotateOnStartup;
            return this;
        }

        public Builder installShutdownHook(boolean installShutdownHook) {
            this.installShutdownHook = installShutdownHook;
            return this;
        }

        public Builder shutdownTimeoutMs(long shutdownTimeoutMs) {
            this.shutdownTimeoutMs = shutdownTimeoutMs;
            return this;
        }

        public VeriLoggerConfig build() {
            return new VeriLoggerConfig(this);
        }
    }

}