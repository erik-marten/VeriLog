package io.github.em.verilog.reader;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public interface PublicKeyResolver {
    ECPublicKeyParameters resolveByKeyIdHex(String keyIdHex);
}