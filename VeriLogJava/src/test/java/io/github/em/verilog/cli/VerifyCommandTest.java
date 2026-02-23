package io.github.em.verilog.cli;

import io.github.em.verilog.reader.DirectoryVerifyReport;
import io.github.em.verilog.reader.VeriLogReader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedConstruction;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

final class VerifyCommandTest {

    private PrintStream origOut;
    private PrintStream origErr;
    private ByteArrayOutputStream outBuf;
    private ByteArrayOutputStream errBuf;
    @TempDir
    Path tmp;

    @BeforeEach
    void redirectStd() {
        origOut = System.out;
        origErr = System.err;
        outBuf = new ByteArrayOutputStream();
        errBuf = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outBuf));
        System.setErr(new PrintStream(errBuf));
    }

    @AfterEach
    void restoreStd() {
        System.setOut(origOut);
        System.setErr(origErr);
    }

    @Test
    void should_return_3_and_print_help_when_args_null() {
        int code = new VerifyCommand().run(null);
        assertEquals(3, code);
        assertTrue(outBuf.toString().contains("Usage:"), "should print help");
    }

    @Test
    void should_return_3_and_print_help_when_args_empty() {
        int code = new VerifyCommand().run(new String[0]);
        assertEquals(3, code);
        assertTrue(outBuf.toString().contains("Usage:"), "should print help");
    }

    @Test
    void should_return_3_when_first_arg_not_verify() {
        int code = new VerifyCommand().run(new String[]{"nope"});
        assertEquals(3, code);
        assertTrue(outBuf.toString().contains("Usage:"), "should print help");
    }

    @Test
    void should_return_3_when_neither_dir_nor_file_provided() {
        int code = new VerifyCommand().run(new String[]{"verify", "--dek-hex", "00".repeat(32), "--pub", "k.pem"});
        assertEquals(3, code);
        assertTrue(errBuf.toString().contains("Provide exactly one of --dir or --file"));
    }

    @Test
    void should_return_3_when_both_dir_and_file_provided() {
        int code = new VerifyCommand().run(new String[]{
                "verify",
                "--dir", "logs",
                "--file", "a.vlog",
                "--dek-hex", "00".repeat(32),
                "--pub", "k.pem"
        });
        assertEquals(3, code);
        assertTrue(errBuf.toString().contains("Provide exactly one of --dir or --file"));
    }

    @Test
    void should_return_3_when_dek_missing() {
        int code = new VerifyCommand().run(new String[]{"verify", "--file", "a.vlog", "--pub", "k.pem"});
        assertEquals(3, code);
        assertTrue(errBuf.toString().contains("Provide --dek-hex"));
    }

    @Test
    void should_return_3_when_pub_missing() {
        int code = new VerifyCommand().run(new String[]{"verify", "--file", "a.vlog", "--dek-hex", "00".repeat(32)});
        assertEquals(3, code);
        assertTrue(errBuf.toString().contains("Provide at least one --pub"));
    }

    @Test
    void should_return_3_when_unexpected_arg_not_starting_with_dashes() {
        int code = new VerifyCommand().run(new String[]{"verify", "oops"});
        assertEquals(3, code);
        assertTrue(errBuf.toString().contains("Unexpected arg"));
    }

    @Test
    void should_return_3_when_flag_value_missing() {
        int code = new VerifyCommand().run(new String[]{"verify", "--dir"});
        assertEquals(3, code);
        assertTrue(errBuf.toString().contains("Missing value for --dir"));
    }

    @Test
    void should_parse_pub_csv_trim_blanks_and_call_verifyFile_with_tolerate_partial_true() throws Exception {
        // Arrange: create two PEM files
        Path pem1 = tmp.resolve("a.pem");
        Path pem2 = tmp.resolve("b.pem");
        writePublicKeyPem(pem1);
        writePublicKeyPem(pem2);

        Path file = tmp.resolve("one.vlog");
        Files.writeString(file, "dummy"); // file existence not required by VerifyCommand itself

        Object okRep = newVerifyReport(true, 42L, null);

        // Mock construction of VeriLogReader so real vlog file needed
        try (MockedConstruction<?> mocked = mockConstruction(
                Class.forName("io.github.em.verilog.reader.VeriLogReader"),
                (mock, ctx) -> {
                    // verifyFile(Path, byte[], PublicKeyResolver, boolean tolerate)
                    when(invokeVerifyFile(mock, any(Path.class), any(byte[].class), any(), eq(true)))
                            .thenReturn(okRep);
                }
        )) {
            // Act
            String dekHex = "00".repeat(32);
            int code = new VerifyCommand().run(new String[]{
                    "verify",
                    "--file", file.toString(),
                    "--dek-hex", dekHex,
                    "--pub", "  " + pem1 + " , , " + pem2 + "  ",
                    "--tolerate-partial", "true"
            });

            // Assert
            assertEquals(0, code);

            String out = outBuf.toString();
            assertTrue(out.contains("one.vlog -> OK"), "should print OK line");
            assertTrue(out.contains("lastSeq=42"), "should print seq");
            assertTrue(errBuf.toString().isBlank(), "no error output expected");
            assertEquals(1, mocked.constructed().size(), "VeriLogReader should be constructed once");
        }
    }

    @Test
    void should_print_fail_for_file_and_return_2_when_verifyFile_reports_failure() throws Exception {
        Path pem = tmp.resolve("k.pem");
        writePublicKeyPem(pem);

        Path file = tmp.resolve("bad.vlog");
        Files.writeString(file, "dummy");

        Object failRep = newVerifyReport(false, 7L, "signature invalid");

        try (MockedConstruction<?> mocked = mockConstruction(
                Class.forName("io.github.em.verilog.reader.VeriLogReader"),
                (mock, ctx) -> when(invokeVerifyFile(mock, any(Path.class), any(byte[].class), any(), anyBoolean()))
                        .thenReturn(failRep)
        )) {
            int code = new VerifyCommand().run(new String[]{
                    "verify",
                    "--file", file.toString(),
                    "--dek-hex", "00".repeat(32),
                    "--pub", pem.toString()
            });

            assertEquals(2, code);

            String out = outBuf.toString();
            assertTrue(out.contains("bad.vlog -> FAIL"), "should print FAIL line");
            assertTrue(out.contains("seq=7"), "should print fail seq");
            assertTrue(out.contains("signature invalid"), "should print reason");
        }
    }

    @Test
    void should_verify_directory_print_each_result_and_return_0_when_all_ok_and_stop_on_fail_false() throws Exception {
        Path pem = tmp.resolve("k.pem");
        writePublicKeyPem(pem);

        Path dir = tmp.resolve("logs");
        Files.createDirectories(dir);

        DirectoryVerifyReport.FileResult r1 =
                new DirectoryVerifyReport.FileResult(dir.resolve("a.vlog"), true, 10L, null);
        DirectoryVerifyReport.FileResult r2 =
                new DirectoryVerifyReport.FileResult(dir.resolve("b.vlog"), true, 11L, null);

        DirectoryVerifyReport dr = newDirectoryVerifyReport(r1, r2);

        try (MockedConstruction<VeriLogReader> mocked = mockConstruction(
                VeriLogReader.class,
                (mock, ctx) -> when(mock.verifyDirectory(any(Path.class), any(byte[].class), any(), eq(false)))
                        .thenReturn(dr)
        )) {
            int code = new VerifyCommand().run(new String[]{
                    "verify",
                    "--dir", dir.toString(),
                    "--dek-hex", "00".repeat(32),
                    "--pub", pem.toString(),
                    "--stop-on-fail", "false"
            });

            assertEquals(0, code);

            String out = outBuf.toString();
            assertTrue(out.contains("a.vlog -> OK"), "should print OK for a.vlog");
            assertTrue(out.contains("b.vlog -> OK"), "should print OK for b.vlog");
            assertTrue(out.contains("ALL FILES OK"), "should print summary");
        }
    }

    @Test
    void should_verify_directory_print_summary_failed_and_return_2_when_some_failed() throws Exception {
        Path pem = tmp.resolve("k.pem");
        writePublicKeyPem(pem);

        Path dir = tmp.resolve("logs");
        Files.createDirectories(dir);

        DirectoryVerifyReport.FileResult r1 =
                new DirectoryVerifyReport.FileResult(dir.resolve("a.vlog"), true, 10L, null);

        DirectoryVerifyReport.FileResult r2 =
                new DirectoryVerifyReport.FileResult(dir.resolve("b.vlog"), false, 5L, "entryHash mismatch");

        DirectoryVerifyReport dr = newDirectoryVerifyReport(r1, r2);

        try (MockedConstruction<VeriLogReader> mocked = mockConstruction(
                VeriLogReader.class,
                (mock, ctx) -> when(mock.verifyDirectory(any(Path.class), any(byte[].class), any(), anyBoolean()))
                        .thenReturn(dr)
        )) {
            int code = new VerifyCommand().run(new String[]{
                    "verify",
                    "--dir", dir.toString(),
                    "--dek-hex", "00".repeat(32),
                    "--pub", pem.toString()
            });

            assertEquals(2, code);

            String out = outBuf.toString();
            assertTrue(out.contains("a.vlog -> OK"));
            assertTrue(out.contains("b.vlog -> FAIL"));
            assertTrue(out.contains("entryHash mismatch"));
            assertTrue(out.contains("SOME FILES FAILED"), "should print summary");
        }
    }

    // ---------------- helpers ----------------

    private static void writePublicKeyPem(Path path) throws Exception {
        var kpg = java.security.KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        var kp = kpg.generateKeyPair();

        byte[] spki = kp.getPublic().getEncoded(); // SubjectPublicKeyInfo DER
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(spki);

        String pem = "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n";
        Files.writeString(path, pem, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private static Object newVerifyReport(boolean ok, long seq, String reason) throws Exception {
        Class<?> cls = Class.forName("io.github.em.verilog.reader.VerifyReport");
        try {
            if (ok) {
                Method m = cls.getDeclaredMethod("ok");
                m.setAccessible(true);
                return m.invoke(null);
            } else {
                Method m = cls.getDeclaredMethod("fail", long.class, String.class);
                m.setAccessible(true);
                return m.invoke(null, seq, reason);
            }
        } catch (NoSuchMethodException ignore) {
            // Fallback: constructor (boolean,long,String)
            Constructor<?> c = cls.getDeclaredConstructor(boolean.class, long.class, String.class);
            c.setAccessible(true);
            return c.newInstance(ok, seq, reason);
        }
    }

    private static DirectoryVerifyReport newDirectoryVerifyReport(DirectoryVerifyReport.FileResult... results) throws Exception {
        DirectoryVerifyReport dr = new DirectoryVerifyReport();

        Method add = DirectoryVerifyReport.class.getDeclaredMethod("add", DirectoryVerifyReport.FileResult.class);
        add.setAccessible(true);

        for (DirectoryVerifyReport.FileResult r : results) {
            add.invoke(dr, r);
        }
        return dr;
    }

    private static Object invokeVerifyFile(Object readerMock, Object fileMatcher, Object dekMatcher, Object resolverMatcher, boolean tolerate) throws Exception {
        Method m = readerMock.getClass().getMethod("verifyFile",
                Path.class, byte[].class, Class.forName("io.github.em.verilog.reader.PublicKeyResolver"), boolean.class);
        return m.invoke(readerMock, fileMatcher, dekMatcher, resolverMatcher, tolerate);
    }
}
