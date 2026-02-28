package io.github.em.verilog.reader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.em.verilog.errors.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class VeriLogReaderTest {
    private VeriLogReader reader;
    private byte[] dek32;
    private PublicKeyResolver resolver;
    private static final ObjectMapper OM = new ObjectMapper();

    @BeforeEach
    void setup() {
        reader = new VeriLogReader();
        dek32 = new byte[32];
        resolver = keyId -> null; // default: unknown key
    }

    @Test
    void should_throw_json_exception_when_header_is_invalid() {
        Path file = TestFiles.invalidHeaderFile();

        VeriLogJsonException ex = assertThrows(
                VeriLogJsonException.class,
                () -> reader.verifyFile(file, dek32, resolver)
        );

        assertEquals("json.invalid_header", ex.getMessageKey());
    }

    @Test
    void should_throw_io_exception_when_file_does_not_exist() {

        Path file = Path.of("does-not-exist.vlog");

        VeriLogIoException ex = assertThrows(
                VeriLogIoException.class,
                () -> reader.verifyFile(file, dek32, resolver)
        );

        assertEquals("io.read_failed", ex.getMessageKey());
    }

    @Test
    void should_fail_when_decryption_fails() throws Exception {

        Path file = TestFiles.encryptedWithWrongKey();

        VerifyReport report = reader.verifyFile(file, dek32, resolver);

        assertFalse(report.valid);
        assertEquals("decrypt/auth failed", report.reason);
    }

    @Test
    void should_fail_when_keyId_is_unknown() throws Exception {

        Path file = TestFiles.validButUnknownKeyId();

        VerifyReport report = reader.verifyFile(file, dek32, resolver);

        assertFalse(report.valid);
        assertTrue(report.reason.startsWith("unknown keyId"));
    }

    @Test
    void should_fail_when_signature_is_invalid() throws Exception {
        var tm = TestFiles.material(); // provides a resolver that returns the pubkey

        VerifyReport report = reader.verifyFile(
                TestFiles.tamperedSignature(),
                tm.dek32,
                tm.keyResolver
        );

        assertFalse(report.valid);
        assertEquals("signature invalid", report.reason);
    }

    @Test
    void should_stop_on_first_failure_when_configured() throws Exception {

        Path dir = TestFiles.directoryWithOneBrokenFile();

        DirectoryVerifyReport report =
                reader.verifyDirectory(dir, dek32, resolver, true);

        assertEquals(1, report.results().size());
    }

    @Test
    void should_continue_on_failure_when_stopOnFirstFailure_is_false() throws Exception {

        Path dir = TestFiles.directoryWithMultipleBrokenFiles();

        DirectoryVerifyReport report =
                reader.verifyDirectory(dir, dek32, resolver, false);

        assertTrue(report.results().size() > 1);
    }

    @Test
    void should_throw_when_a_file_has_invalid_header_json_in_directory() throws Exception {
        Path dir = TestFiles.directoryWithInvalidHeaderFirst();

        VeriLogJsonException ex = assertThrows(
                VeriLogJsonException.class,
                () -> reader.verifyDirectory(dir, dek32, resolver, false)
        );

        assertEquals("json.invalid_header", ex.getMessageKey());
    }

    @Test
    void should_wrap_ioexception_as_io_read_failed() throws Exception {
        Path path = Path.of("dummy.vlog");
        resolver = mock(PublicKeyResolver.class);

        byte[] headerJson = "{\"aad\":\"VeriLog|v1\"}".getBytes(StandardCharsets.UTF_8);

        try (MockedConstruction<FramedFileReader> mocked =
                     mockConstruction(FramedFileReader.class, (mock, context) -> {

                         // Prevent NPE in readHeader()
                         when(mock.rawHeaderJsonBytes()).thenReturn(headerJson);
                         doThrow(new IOException("boom"))
                                 .when(mock)
                                 .positionAtFirstFrame();
                     })) {

            VeriLogIoException ex = assertThrows(
                    VeriLogIoException.class,
                    () -> reader.verifyFile(path, dek32, resolver, false)
            );

            assertEquals("io.read_failed", ex.getMessageKey());
            assertTrue(ex.getCause() instanceof IOException);
            assertEquals("boom", ex.getCause().getMessage());
        }
    }

    @Test
    void should_throw_when_header_empty() throws Exception {
        Path path = Path.of("dummy.vlog");
        resolver = mock(PublicKeyResolver.class);

        try (MockedConstruction<FramedFileReader> mocked =
                     mockConstruction(FramedFileReader.class, (mock, context) -> {
                         doThrow(new IOException("boom"))
                                 .when(mock)
                                 .positionAtFirstFrame();
                     })) {
            VeriLogFormatException ex = assertThrows(
                    VeriLogFormatException.class,
                    () -> reader.verifyFile(path, dek32, resolver, false)
            );

            assertEquals("format.missing_header", ex.getMessageKey());
            assertEquals("The file does not contain a valid header section dummy.vlog", ex.getMessage());
        }
    }

    @Test
    void should_fail_when_any_required_field_missing() {
        // given: missing "sig"
        ObjectNode signed = OM.createObjectNode();
        signed.put("seq", 1);
        signed.put("prevHash", "0".repeat(64));
        signed.put("entryHash", "a".repeat(64));
        signed.put("keyId", "b".repeat(64));
        // signed.put("sig", "..."); // missing

        Frame f = new Frame((byte) 1, 1L, new byte[24], new byte[0]);
        VerifyReport r = invokeVerifyRequiredFields(reader, signed, f);

        assertNotNull(r);
        assertFalse(r.valid);
        assertEquals(1L, r.seq);
        assertTrue(r.reason.contains("missing required fields"));
    }

    @Test
    void should_wrap_files_list_ioexception_as_io_read_failed() throws Exception {
        Path dir = Path.of("dummy-dir");
        try (MockedStatic<Files> files = mockStatic(Files.class)) {
            files.when(() -> Files.list(dir)).thenThrow(new IOException("boom"));

            VeriLogIoException ex = assertThrows(
                    VeriLogIoException.class,
                    () -> reader.verifyDirectory(dir, new byte[32], mock(PublicKeyResolver.class), false)
            );

            assertEquals("io.read_failed", ex.getMessageKey());
            assertTrue(ex.getCause() instanceof IOException);
        }
    }

    @Test
    void should_wrap_runtimeexception_as_json_canonicalize_failed() throws Exception {
        JsonNode node = mock(JsonNode.class);
        when(node.deepCopy()).thenThrow(new RuntimeException("boom"));

        var m = VeriLogReader.class.getDeclaredMethod("canonicalizeWithout", JsonNode.class);
        m.setAccessible(true);

        VeriLogJsonException ex = assertThrows(
                VeriLogJsonException.class,
                () -> {
                    try {
                        m.invoke(reader, node);
                    } catch (java.lang.reflect.InvocationTargetException ite) {
                        throw ite.getCause(); // unwrap
                    }
                }
        );

        assertEquals("json.canonicalize_failed", ex.getMessageKey());
        assertNotNull(ex.getCause());
        assertEquals("boom", ex.getCause().getMessage());
    }

    @Test
    void should_wrap_crypto_exception_from_verifier_as_crypto_verify_failed_with_seq_context() throws Exception {
        var tm = TestFiles.material();
        Path file = TestFiles.tamperedSignature(); // reaches verifyEntryHashSig() call

        // Force the static verifier to throw a crypto exception (unexpected crypto/provider failure)
        try (MockedStatic<BcEcdsaVerifier> mocked = mockStatic(BcEcdsaVerifier.class)) {
            mocked.when(() -> BcEcdsaVerifier.verifyEntryHashSig(
                            any(),               // ECPublicKeyParameters
                            any(byte[].class),   // entryHashBytes
                            any(byte[].class)    // sigRaw
                    ))
                    .thenThrow(new VeriLogCryptoException("crypto.sig_encode_failed"));

            // Act
            VeriLogCryptoException ex = assertThrows(
                    VeriLogCryptoException.class,
                    () -> reader.verifyFile(file, tm.dek32, tm.keyResolver)
            );

            assertEquals("crypto.verify_failed", ex.getMessageKey());
            // preserve the original crypto failure as the cause
            assertNotNull(ex.getCause());
            assertTrue(ex.getCause() instanceof VeriLogCryptoException);
            assertEquals("crypto.sig_encode_failed", ((VeriLogCryptoException) ex.getCause()).getMessageKey());
            assertArrayEquals(new Object[]{"seq", "1"}, ex.getMessageArgs());
        }
    }

    @ParameterizedTest
    @MethodSource("provideNullValues")
    void should_throw_when_param_is_null(Path path, byte[] dek32, PublicKeyResolver publicKeyResolver) {
        assertThrows(NullPointerException.class, () -> reader.verifyDirectory(path, dek32, publicKeyResolver));
    }

    @ParameterizedTest
    @MethodSource("missingRequiredFieldCases")
    void should_fail_when_required_field_missing_or_null(String field, boolean asNull) {
        ObjectNode signed = validSigned();

        if (asNull) {
            signed.putNull(field);
        } else {
            signed.remove(field);
        }

        Frame f = new Frame((byte) 1, 7L, new byte[24], new byte[0]);
        VerifyReport r = invokeVerifyRequiredFields(reader, signed, f);

        assertNotNull(r);
        assertEquals(7L, r.seq);
        assertFalse(r.valid);
        assertTrue(r.reason.contains("missing required fields"));
    }

    private static Stream<Arguments> provideNullValues() {
        PublicKeyResolver resolver = mock(PublicKeyResolver.class);
        Path path = Path.of("dummy.vlog");
        return Stream.of(
                Arguments.of(null, new byte[32], resolver),
                Arguments.of(path, null, resolver),
                Arguments.of(path, new byte[32], null)
        );
    }

    private static Stream<Arguments> missingRequiredFieldCases() {
        return Stream.of(
                Arguments.of("seq", false),
                Arguments.of("seq", true),
                Arguments.of("prevHash", false),
                Arguments.of("prevHash", true),
                Arguments.of("entryHash", false),
                Arguments.of("entryHash", true),
                Arguments.of("keyId", false),
                Arguments.of("keyId", true),
                Arguments.of("sig", false),
                Arguments.of("sig", true)
        );
    }

    private static ObjectNode validSigned() {
        ObjectNode signed = OM.createObjectNode();
        signed.put("seq", 7);
        signed.put("prevHash", "0".repeat(64));
        signed.put("entryHash", "a".repeat(64));
        signed.put("keyId", "b".repeat(64));
        signed.put("sig", "AAAA");
        return signed;
    }

    // reflection helper
    private static VerifyReport invokeVerifyRequiredFields(VeriLogReader reader, ObjectNode signed, Frame f) {
        try {
            var m = VeriLogReader.class.getDeclaredMethod(
                    "verifyRequiredFields",
                    com.fasterxml.jackson.databind.JsonNode.class,
                    Frame.class
            );
            m.setAccessible(true);
            return (VerifyReport) m.invoke(reader, signed, f);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

