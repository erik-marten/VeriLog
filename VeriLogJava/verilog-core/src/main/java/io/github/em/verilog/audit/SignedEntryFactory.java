/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.em.verilog.CanonicalJson;
import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.errors.VeriLogCryptoException;
import io.github.em.verilog.errors.VeriLogJsonException;
import io.github.em.verilog.sign.LogSigner;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

public final class SignedEntryFactory {

    private final ObjectMapper om = new ObjectMapper();

    /**
     * Compatibility overload for the original structured arguments.
     *
     * <p>This method delegates through {@link AuditEvent} and therefore applies
     * {@code AuditEvent}'s validation and supported-data rules.</p>
     */
    public byte[] buildSignedEntryJsonUtf8(
            HashChainState chain,
            LogSigner signer,
            String actor,
            String eventType,
            Map<String, Object> event,
            Instant tsUtc
    ) throws VeriLogCryptoException {
        return buildSignedEntryJsonUtf8(
                chain,
                signer,
                new AuditEvent(tsUtc, actor, eventType, event)
        );
    }

    public byte[] buildSignedEntryJsonUtf8(
            HashChainState chain,
            LogSigner signer,
            AuditEvent event
    ) throws VeriLogCryptoException {
        Objects.requireNonNull(chain, "chain");
        Objects.requireNonNull(signer, "signer");
        Objects.requireNonNull(event, "event");

        long seq = chain.allocateSeq();

        ObjectNode unsigned = om.createObjectNode();
        unsigned.put("version", 1);
        unsigned.put("seq", seq);
        unsigned.put("ts", event.timestamp().toString());
        unsigned.put("actor", event.actor());
        unsigned.put("eventType", event.eventType());
        unsigned.set("event", om.valueToTree(event.data()));
        unsigned.put("prevHash", chain.prevHashHex());
        unsigned.put("keyId", signer.keyId());

        String canonicalPayload = CanonicalJson.canonicalize(unsigned);
        byte[] entryHashBytes = CryptoUtil.sha256Utf8(canonicalPayload);
        String entryHashHex = CryptoUtil.toHexLower(entryHashBytes);

        byte[] sigRaw = signer.signEntryHash(entryHashBytes);
        String sigB64 = Base64.getEncoder().encodeToString(sigRaw);

        ObjectNode signed = unsigned.deepCopy();
        signed.put("entryHash", entryHashHex);
        signed.put("sig", sigB64);

        chain.updatePrevHash(entryHashHex);

        return signed.toString().getBytes(StandardCharsets.UTF_8);
    }
}
