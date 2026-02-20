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