package io.github.em.verilog.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

final class VeriLogCliTest {

    @Test
    void should_exit_with_code_from_verify_command() {
        SecurityManager original = System.getSecurityManager();
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            ExitException ex = assertThrows(ExitException.class,
                    () -> VeriLogCli.main(new String[0])); // args empty -> VerifyCommand returns 3

            assertEquals(3, ex.status);

        } finally {
            System.setSecurityManager(original);
        }
    }

    static final class ExitException extends SecurityException {
        final int status;
        ExitException(int status) { this.status = status; }
    }

    static final class NoExitSecurityManager extends SecurityManager {
        @Override public void checkPermission(java.security.Permission perm) { }
        @Override public void checkPermission(java.security.Permission perm, Object context) { }
        @Override public void checkExit(int status) { throw new ExitException(status); }
    }
}