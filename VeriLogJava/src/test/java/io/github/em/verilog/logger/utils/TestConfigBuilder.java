package io.github.em.verilog.logger.utils;

import io.github.em.verilog.logger.VeriLoggerConfig;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class TestConfigBuilder {
    public static VeriLoggerConfig.Builder configBuilder(Path dir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();

        return new VeriLoggerConfig.Builder()
                .logDir(dir)
                .currentFileName("current.vlog")
                .filePrefix("verilog-")
                .rotateOnStartup(true)
                .rotateBytes(1024 * 1024)
                .flushEveryN(10)
                .flushEveryMs(50)
                .fsyncOnFlush(false)
                .encryptionKey(new byte[32])
                .aadPrefix("test-aad")
                .signer(new TestLogSigner(kp.getPrivate(), kp.getPublic()))
                .actor("test-actor");
    }
}
