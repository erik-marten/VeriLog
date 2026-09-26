package io.github.em.verilog.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mockStatic;

final class VeriLogCliTest {

    @Test
    void should_exit_with_code_from_verify_command() {
        assertEquals(3, VeriLogCli.execute(new String[0]));
    }

    @Test
    void run_should_return_3_when_not_verify_command() {
        int code = new VerifyCommand().run(new String[0]);
        assertEquals(3, code);
    }

    @Test
    void run_should_return_4_on_unexpected_error() {
        int code = new VerifyCommand().run(new String[]{
                "verify",
                "--file", "dummy.vlog",
                "--dek-hex", "00".repeat(32),
                "--pub", "does-not-exist.pem"
        });

        assertEquals(4, code);
    }

    @Test
    void main_should_not_terminate_jvm_and_should_capture_exit_code() {
        var original = VeriLogCli.exitHook;
        var captured = new java.util.concurrent.atomic.AtomicInteger(Integer.MIN_VALUE);

        try {
            VeriLogCli.exitHook = captured::set;

            VeriLogCli.main(new String[0]); // VerifyCommand.run([]) -> 3

            assertEquals(3, captured.get());
        } finally {
            VeriLogCli.exitHook = original;
        }
    }
}