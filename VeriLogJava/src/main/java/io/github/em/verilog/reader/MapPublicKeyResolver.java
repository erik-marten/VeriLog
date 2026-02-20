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