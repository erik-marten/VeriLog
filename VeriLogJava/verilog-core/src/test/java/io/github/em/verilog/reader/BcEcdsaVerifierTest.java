package io.github.em.verilog.reader;

import io.github.em.verilog.errors.VeriLogCryptoException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BcEcdsaVerifierTest {

    private final DSAEncoding original = BcEcdsaVerifier.dsaEncoding;

    @AfterEach
    void restoreEncoding() {
        BcEcdsaVerifier.dsaEncoding = original;
    }

    @Test
    void should_return_false_when_der_decode_throws_io_exception() throws Exception {
        // Arrange
        ECPublicKeyParameters pub = mock(ECPublicKeyParameters.class, RETURNS_DEEP_STUBS);
        when(pub.getParameters().getN()).thenReturn(BigInteger.valueOf(23));

        byte[] entryHash32 = new byte[32];
        byte[] sigRaw64 = new byte[64]; // any 64 bytes; rawToDer will produce DER

        DSAEncoding encoding = mock(DSAEncoding.class);
        when(encoding.decode(any(BigInteger.class), any(byte[].class)))
                .thenThrow(new IOException("boom"));

        BcEcdsaVerifier.dsaEncoding = encoding;

        // Act
        boolean ok = BcEcdsaVerifier.verifyEntryHashSig(pub, entryHash32, sigRaw64);

        // Assert
        assertFalse(ok);
        verify(encoding).decode(any(BigInteger.class), any(byte[].class));
    }

    @Test
    void should_throw_crypto_exception_when_der_decode_throws_runtime_exception() throws Exception {
        ECPublicKeyParameters pub = mock(ECPublicKeyParameters.class, RETURNS_DEEP_STUBS);
        when(pub.getParameters().getN()).thenReturn(BigInteger.valueOf(23));

        byte[] entryHash32 = new byte[32];
        byte[] sigRaw64 = new byte[64];

        DSAEncoding encoding = mock(DSAEncoding.class);
        when(encoding.decode(any(BigInteger.class), any(byte[].class)))
                .thenThrow(new RuntimeException("boom"));

        BcEcdsaVerifier.dsaEncoding = encoding;

        VeriLogCryptoException ex = assertThrows(
                VeriLogCryptoException.class,
                () -> BcEcdsaVerifier.verifyEntryHashSig(pub, entryHash32, sigRaw64)
        );
        assertEquals("crypto.sig_decode_failed", ex.getMessageKey());
    }
}