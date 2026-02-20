package io.github.em.verilog.sign;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.StringReader;

public final class BcPemKeys {
    private BcPemKeys() {}

    public static byte[] readPkcs8PrivateKeyDer(String pem) {
        try (PemReader r = new PemReader(new StringReader(pem))) {
            var obj = r.readPemObject();
            if (obj == null) throw new IllegalArgumentException("Empty PEM");
            // Usually "PRIVATE KEY" for PKCS8
            return obj.getContent();
        } catch (Exception e) {
            throw new RuntimeException("Failed to read private key PEM", e);
        }
    }

    public static byte[] readSpkiPublicKeyDer(String pem) {
        try (PemReader r = new PemReader(new StringReader(pem))) {
            var obj = r.readPemObject();
            if (obj == null) throw new IllegalArgumentException("Empty PEM");
            // Usually "PUBLIC KEY" for SPKI
            return obj.getContent();
        } catch (Exception e) {
            throw new RuntimeException("Failed to read public key PEM", e);
        }
    }
}