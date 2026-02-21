/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.reader;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.util.Map;

public final class MapPublicKeyResolver implements PublicKeyResolver {
    private final Map<String, ECPublicKeyParameters> map;

    public MapPublicKeyResolver(Map<String, ECPublicKeyParameters> map) {
        this.map = map;
    }

    @Override
    public ECPublicKeyParameters resolveByKeyIdHex(String keyIdHex) {
        return map.get(keyIdHex);
    }
}