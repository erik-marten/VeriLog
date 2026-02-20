package io.github.em.verilog.logger;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class RotationPolicyTest {

    @Test
    void should_create_rotated_filename_when_rotating_with_prefix_and_vlog_extension_and_no_colon() {
        RotationPolicy rp = new RotationPolicy(10, "app");
        Path out = rp.rotatedPath(Path.of("/tmp/logs"));

        String name = out.getFileName().toString();
        assertTrue(name.startsWith("app-"));
        assertTrue(name.endsWith(".vlog"));
        assertFalse(name.contains(":"), "Filename must not contain ':' (Windows-unfriendly)");
    }
}