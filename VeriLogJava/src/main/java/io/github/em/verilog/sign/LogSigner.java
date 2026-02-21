/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.sign;

public interface LogSigner {
    /** stable identifier for the public key (e.g. hex(sha256(SPKI_DER))) */
    String keyId();

    /** returns raw signature r||s (64 bytes) */
    byte[] signEntryHash(byte[] entryHash32);
}