package io.github.em.verilog;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class PemKeys {
    private PemKeys() {}

    public static PublicKey importEcPublicKeyFromPem(String pem) {
        try {
            String b64 = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(b64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            return KeyFactory.getInstance("EC").generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse EC public key PEM", e);
        }
    }
}