/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.logback;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.encoder.Encoder;
import ch.qos.logback.core.rolling.RollingFileAppender;
import ch.qos.logback.core.rolling.RollingPolicy;
import ch.qos.logback.core.rolling.TriggeringPolicy;
import ch.qos.logback.core.rolling.helper.CompressionMode;
import io.github.em.verilog.audit.HashChainState;
import io.github.em.verilog.io.FramedTailRepair;
import io.github.em.verilog.reader.PublicKeyResolver;
import io.github.em.verilog.reader.VeriLogReader;
import io.github.em.verilog.sign.LogSigner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * A managed VeriLog encoder on Logback's normal rolling file lifecycle.
 * Recovery requires the full local chain from sequence 1. If retention removes
 * its root while later files remain, restart fails verification.
 */
public final class VeriLogRollingFileAppender extends RollingFileAppender<ILoggingEvent> {
    private String actor;
    private LogSigner signer;
    private PublicKeyResolver keyResolver;
    private byte[] dek32;
    private String aadPrefix;
    private VeriLogEncoder managedEncoder;
    private boolean startedOnce;

    public void setActor(String actor) {
        requireConfigurable();
        this.actor = actor;
    }

    public void setSigner(LogSigner signer) {
        requireConfigurable();
        this.signer = signer;
    }

    public void setPublicKeyResolver(PublicKeyResolver keyResolver) {
        requireConfigurable();
        this.keyResolver = keyResolver;
    }

    public void setDek32(byte[] dek32) {
        requireConfigurable();
        this.dek32 = dek32 == null ? null : dek32.clone();
    }

    public void setAadPrefix(String aadPrefix) {
        requireConfigurable();
        this.aadPrefix = aadPrefix;
    }

    @Override
    public void setFile(String file) {
        requireConfigurable();
        super.setFile(file);
    }

    @Override
    public void setAppend(boolean append) {
        requireConfigurable();
        super.setAppend(append);
    }

    @Override
    public void setPrudent(boolean prudent) {
        requireConfigurable();
        super.setPrudent(prudent);
    }

    @Override
    public void setRollingPolicy(RollingPolicy policy) {
        requireConfigurable();
        super.setRollingPolicy(policy);
    }

    @Override
    public void setTriggeringPolicy(TriggeringPolicy<ILoggingEvent> policy) {
        requireConfigurable();
        super.setTriggeringPolicy(policy);
    }

    /** The encoder is created only after cryptographic recovery. */
    @Override
    public void setEncoder(Encoder<ILoggingEvent> encoder) {
        throw new IllegalStateException("VeriLogRollingFileAppender manages its own encoder");
    }

    @Override
    public void start() {
        if (isStarted()) return;
        if (startedOnce) {
            addError("VeriLog appender cannot restart; create a new instance to recover chain state");
            return;
        }
        if (!validateConfiguration()) return;

        final Path active;
        try {
            String activeName = getRollingPolicy().getActiveFileName();
            if (activeName == null || activeName.isBlank()) {
                addError("VeriLog rolling policy supplied no active file name");
                return;
            }
            active = Path.of(activeName).toAbsolutePath().normalize();
            if (!active.getFileName().toString().endsWith(".vlog")) {
                addError("VeriLog active file must end in .vlog for directory recovery: " + active);
                return;
            }
        } catch (RuntimeException e) {
            addError("Could not determine VeriLog active file from rolling policy", e);
            return;
        }

        Path directory = active.getParent();
        try {
            Files.createDirectories(directory);
            if (!Files.isDirectory(directory) || !Files.isReadable(directory) || !Files.isWritable(directory)) {
                throw new IOException("Recovery directory is inaccessible: " + directory);
            }
            rejectCompressedArchives(directory);
            boolean resume = Files.exists(active) && Files.size(active) > 0;
            HashChainState state = new VeriLogReader().recoverChainState(directory, active, dek32, keyResolver);
            if (resume) FramedTailRepair.truncateIncompleteTail(active);

            VeriLogEncoder encoder = new VeriLogEncoder();
            encoder.setContext(getContext());
            encoder.setActor(actor);
            encoder.setSigner(signer);
            encoder.setDek32(dek32);
            encoder.setAadPrefix(aadPrefix);
            encoder.setInitialChainState(state);
            encoder.setInitialStreamMode(resume
                    ? VeriLogEncoder.InitialStreamMode.RESUME : VeriLogEncoder.InitialStreamMode.NEW);
            encoder.start();
            if (!encoder.isStarted()) {
                addError("Managed VeriLog encoder failed to start");
                return;
            }
            managedEncoder = encoder;
            super.setEncoder(encoder);
            startedOnce = true;
            boolean startedSuccessfully = false;
            try {
                super.start();
                startedSuccessfully = isStarted();
            } finally {
                if (!startedSuccessfully) {
                    if (isStarted()) super.stop();
                    else closeOutputStream();
                    encoder.stop();
                }
            }
        } catch (Exception e) {
            if (managedEncoder != null) managedEncoder.stop();
            addError("VeriLog startup recovery or tail repair failed for " + active + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void stop() {
        super.stop();
        if (managedEncoder != null) managedEncoder.stop();
    }

    private boolean validateConfiguration() {
        boolean valid = true;
        if (actor == null || actor.isBlank()) { addError("VeriLog actor is required"); valid = false; }
        if (signer == null) { addError("VeriLog signer is required"); valid = false; }
        if (keyResolver == null) { addError("VeriLog public key resolver is required"); valid = false; }
        if (dek32 == null || dek32.length != 32) { addError("VeriLog DEK must be 32 bytes"); valid = false; }
        if (aadPrefix == null || aadPrefix.isBlank()) { addError("VeriLog AAD prefix is required"); valid = false; }
        RollingPolicy rollingPolicy = getRollingPolicy();
        TriggeringPolicy<ILoggingEvent> triggeringPolicy = getTriggeringPolicy();
        if (rollingPolicy == null || !rollingPolicy.isStarted()) {
            addError("VeriLog rolling policy must be configured and started"); valid = false;
        }
        if (triggeringPolicy == null || !triggeringPolicy.isStarted()) {
            addError("VeriLog triggering policy must be configured and started"); valid = false;
        }
        if (!isAppend()) { addError("VeriLog requires append=true"); valid = false; }
        if (isPrudent()) { addError("VeriLog does not support prudent mode"); valid = false; }
        if (rollingPolicy != null && rollingPolicy.isStarted()
                && rollingPolicy.getCompressionMode() != CompressionMode.NONE) {
            addError("VeriLog does not support compressed rolling archives"); valid = false;
        }
        return valid;
    }

    private void rejectCompressedArchives(Path directory) throws IOException {
        try (Stream<Path> files = Files.list(directory)) {
            if (files.filter(Files::isRegularFile).anyMatch(path -> {
                String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
                return name.endsWith(".vlog.gz") || name.endsWith(".vlog.zip") || name.endsWith(".vlog.xz");
            })) {
                throw new IOException("Compressed VeriLog archive found in " + directory
                        + "; decompression is unsupported");
            }
        }
    }

    private void requireConfigurable() {
        if (startedOnce) throw new IllegalStateException("VeriLog security configuration cannot change after startup");
    }
}
