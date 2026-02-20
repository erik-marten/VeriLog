package io.github.em.verilog.sign;

public interface LogSigner {
    /** stable identifier for the public key (e.g. hex(sha256(SPKI_DER))) */
    String keyId();

    /** returns raw signature r||s (64 bytes) */
    byte[] signEntryHash(byte[] entryHash32);
}