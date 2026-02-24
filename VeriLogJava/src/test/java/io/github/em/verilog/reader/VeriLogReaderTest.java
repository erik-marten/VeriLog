package io.github.em.verilog.reader;

import io.github.em.verilog.errors.VeriLogIoException;
import io.github.em.verilog.errors.VeriLogJsonException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class VeriLogReaderTest {
    private VeriLogReader reader;
    private byte[] dek32;
    private PublicKeyResolver resolver;

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
}
