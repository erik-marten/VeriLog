package io.github.em.verilog.reader;

import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.EcdsaSigCodec;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;

import java.math.BigInteger;

public final class BcEcdsaVerifier {
    private BcEcdsaVerifier() {}

    public static boolean verifyEntryHashSig(ECPublicKeyParameters pub, byte[] entryHash32, byte[] sigRaw64) {
        if (entryHash32 == null || entryHash32.length != 32) throw new IllegalArgumentException("entryHash must be 32 bytes");
        if (sigRaw64 == null || sigRaw64.length != 64) throw new IllegalArgumentException("sig must be 64 bytes");

        // must match signer: sign SHA256(entryHashBytes)
        byte[] digest = CryptoUtil.sha256(entryHash32);

        byte[] der = EcdsaSigCodec.rawToDer(sigRaw64);
        BigInteger[] rs;
        try {
            rs = StandardDSAEncoding.INSTANCE.decode(pub.getParameters().getN(), der);
        } catch (Exception e) {
            return false;
        }

        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, pub);
        return verifier.verifySignature(digest, rs[0], rs[1]);
    }
}