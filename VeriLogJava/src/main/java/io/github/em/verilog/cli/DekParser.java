/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.cli;

import io.github.em.verilog.CryptoUtil;

import java.util.Base64;
import java.util.Map;

final class DekParser {
    private DekParser() {}

    static byte[] parseDek(Map<String, String> flags) {
        if (flags.containsKey("dek-hex")) {
            String hex = flags.get("dek-hex").trim();
            byte[] b = CryptoUtil.fromHex(hex);
            if (b.length != 32) throw new IllegalArgumentException("--dek-hex must decode to 32 bytes");
            return b;
        }
        if (flags.containsKey("dek-b64")) {
            byte[] b = Base64.getDecoder().decode(flags.get("dek-b64").trim());
            if (b.length != 32) throw new IllegalArgumentException("--dek-b64 must decode to 32 bytes");
            return b;
        }
        return null;
    }
}