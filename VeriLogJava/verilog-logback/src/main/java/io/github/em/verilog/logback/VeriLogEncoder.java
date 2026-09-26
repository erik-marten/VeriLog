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
import ch.qos.logback.core.encoder.EncoderBase;
import io.github.em.verilog.audit.AuditEvent;
import io.github.em.verilog.audit.HashChainState;
import io.github.em.verilog.audit.SignedEntryFactory;
import io.github.em.verilog.errors.VeriLogCryptoException;
import io.github.em.verilog.io.EncryptedFrameCodec;
import io.github.em.verilog.io.FramedLogFile;
import io.github.em.verilog.io.VlogHeaderCodec;
import io.github.em.verilog.sign.LogSigner;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.Optional;

/** A stateful encoder for explicitly marked audit events. The caller supplies recovered chain state. */
public final class VeriLogEncoder extends EncoderBase<ILoggingEvent> {

    public enum InitialStreamMode { NEW, RESUME }

    private final LogbackAuditSemanticsResolver resolver = new LogbackAuditSemanticsResolver();
    private final LogbackAuditEventMapper mapper = new LogbackAuditEventMapper();
    private final SignedEntryFactory signedEntryFactory = new SignedEntryFactory();
    private final VlogHeaderCodec headerCodec = new VlogHeaderCodec();

    private String actor;
    private LogSigner signer;
    private byte[] dek32;
    private String aadPrefix;
    private HashChainState initialChainState;
    private InitialStreamMode initialStreamMode;

    private HashChainState liveChainState;
    private EncryptedFrameCodec frameCodec;
    private boolean firstHeaderCall = true;
    private boolean startedOnce;

    public void setActor(String actor) {
        requireNotStarted();
        this.actor = actor;
    }

    public void setSigner(LogSigner signer) {
        requireNotStarted();
        this.signer = signer;
    }

    public void setDek32(byte[] dek32) {
        requireNotStarted();
        this.dek32 = dek32 == null ? null : dek32.clone();
    }

    public void setAadPrefix(String aadPrefix) {
        requireNotStarted();
        this.aadPrefix = aadPrefix;
    }

    public void setInitialChainState(HashChainState initialChainState) {
        requireNotStarted();
        this.initialChainState = initialChainState == null ? null : copy(initialChainState);
    }

    public void setInitialStreamMode(InitialStreamMode initialStreamMode) {
        requireNotStarted();
        this.initialStreamMode = initialStreamMode;
    }

    @Override
    public void start() {
        if (isStarted()) return;
        if (startedOnce) {
            addError("VeriLog encoder cannot restart; create a new encoder with recovered chain state");
            return;
        }
        boolean valid = true;
        if (actor == null || actor.isBlank()) {
            addError("VeriLog actor must be configured and nonblank");
            valid = false;
        }
        if (signer == null) {
            addError("VeriLog signer must be configured");
            valid = false;
        }
        if (dek32 == null || dek32.length != 32) {
            addError("VeriLog DEK must be 32 bytes");
            valid = false;
        }
        if (aadPrefix == null || aadPrefix.isBlank()) {
            addError("VeriLog AAD prefix must be configured and nonblank");
            valid = false;
        }
        if (initialChainState == null || initialChainState.nextSeq() < 1
                || initialChainState.nextSeq() == Long.MAX_VALUE
                || initialChainState.prevHashHex() == null
                || !initialChainState.prevHashHex().matches("[0-9a-f]{64}")) {
            addError("VeriLog initialized chain state must have a positive sequence and 64-character lowercase hex previous hash");
            valid = false;
        }
        if (initialStreamMode == null) {
            addError("VeriLog initial stream mode must be configured");
            valid = false;
        }
        if (!valid) return;

        frameCodec = new EncryptedFrameCodec(dek32, aadPrefix);
        liveChainState = copy(initialChainState);
        firstHeaderCall = true;
        super.start();
        startedOnce = true;
    }

    @Override
    public boolean isStateful() {
        return true;
    }

    @Override
    public byte[] encode(ILoggingEvent event) {
        requireStarted();
        Optional<String> eventType = resolver.resolveEventType(event);
        if (eventType.isEmpty()) return new byte[0];

        AuditEvent auditEvent = mapper.map(event, actor, eventType.get());
        HashChainState temporary = copy(liveChainState);
        if (temporary.nextSeq() == Long.MAX_VALUE) {
            throw new IllegalStateException("VeriLog sequence exhausted");
        }
        try {
            byte[] signed = signedEntryFactory.buildSignedEntryJsonUtf8(temporary, signer, auditEvent);
            long sequence = temporary.nextSeq() - 1;
            byte[] frame = frameCodec.encode(FramedLogFile.TYPE_LOG, sequence, signed);
            liveChainState = temporary;
            return frame;
        } catch (VeriLogCryptoException e) {
            throw new IllegalStateException("VeriLog signing failed", e);
        }
    }

    @Override
    public byte[] headerBytes() {
        requireStarted();
        if (firstHeaderCall && initialStreamMode == InitialStreamMode.RESUME) {
            firstHeaderCall = false;
            return new byte[0];
        }
        try {
            byte[] header = headerCodec.encode(aadPrefix, Instant.now());
            firstHeaderCall = false;
            return header;
        } catch (IOException e) {
            throw new UncheckedIOException("VeriLog header encoding failed", e);
        }
    }

    @Override
    public byte[] footerBytes() {
        return new byte[0];
    }

    private void requireNotStarted() {
        if (startedOnce) throw new IllegalStateException("VeriLog encoder configuration cannot change after start");
    }

    private void requireStarted() {
        if (!isStarted()) throw new IllegalStateException("VeriLog encoder is not started");
    }

    private static HashChainState copy(HashChainState state) {
        return new HashChainState(state.nextSeq(), state.prevHashHex());
    }
}
