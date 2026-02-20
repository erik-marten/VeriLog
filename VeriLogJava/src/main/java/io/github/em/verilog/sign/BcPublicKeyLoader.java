package io.github.em.verilog.sign;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public final class BcPublicKeyLoader {
    private BcPublicKeyLoader() {}

    public static ECPublicKeyParameters fromSpkiDer(byte[] spkiDer) {
        try {
            var key = PublicKeyFactory.createKey(spkiDer);
            if (!(key instanceof ECPublicKeyParameters)) {
                throw new IllegalArgumentException("Not an EC public key");
            }
            return (ECPublicKeyParameters) key;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key", e);
        }
    }
}