package io.github.em.verilog.example;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.util.LogbackMDCAdapter;
import ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy;
import ch.qos.logback.core.util.FileSize;
import io.github.em.verilog.logback.VeriLogRollingFileAppender;
import io.github.em.verilog.reader.DirectoryVerifyReport;
import io.github.em.verilog.reader.MapPublicKeyResolver;
import io.github.em.verilog.reader.VeriLogReader;
import io.github.em.verilog.sign.BcEcdsaP256Signer;
import io.github.em.verilog.sign.BcPublicKeyLoader;
import org.slf4j.Logger;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws Exception {
        Path logDir = Path.of("build", "verilog-logs").toAbsolutePath();
        Path activeFile = logDir.resolve("current.vlog");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        byte[] dek = new byte[32];
        new SecureRandom().nextBytes(dek);

        byte[] publicKeyDer = keyPair.getPublic().getEncoded();
        BcEcdsaP256Signer signer = new BcEcdsaP256Signer(
                keyPair.getPrivate().getEncoded(), publicKeyDer, true);
        MapPublicKeyResolver resolver = new MapPublicKeyResolver(Map.of(
                signer.keyId(), BcPublicKeyLoader.fromSpkiDer(publicKeyDer)));

        LoggerContext context = new LoggerContext();
        // A standalone context needs an MDC adapter for normal Logback event metadata.
        context.setMDCAdapter(new LogbackMDCAdapter());
        VeriLogRollingFileAppender appender = new VeriLogRollingFileAppender();
        try {
            appender.setContext(context);
            appender.setName("verilog-audit");
            appender.setActor("example-service");
            appender.setSigner(signer);
            appender.setPublicKeyResolver(resolver);
            appender.setDek32(dek);
            appender.setAadPrefix("VeriLog|v1");
            appender.setFile(activeFile.toString());
            appender.setAppend(true);
            appender.setPrudent(false);

            SizeAndTimeBasedRollingPolicy<ILoggingEvent> policy = new SizeAndTimeBasedRollingPolicy<>();
            policy.setContext(context);
            policy.setParent(appender);
            policy.setFileNamePattern(logDir.resolve("archive.%d{yyyy-MM-dd}.%i.vlog").toString());
            policy.setMaxFileSize(FileSize.valueOf("10MB"));
            policy.start();
            if (!policy.isStarted()) {
                throw new IllegalStateException("Logback rolling policy failed to start");
            }
            appender.setRollingPolicy(policy);
            appender.start();
            if (!appender.isStarted()) {
                throw new IllegalStateException("VeriLog appender failed to start");
            }

            ch.qos.logback.classic.Logger logbackLogger = context.getLogger("example-service");
            logbackLogger.addAppender(appender);
            Logger logger = logbackLogger;

            logger.info("Application started");
            logger.atInfo()
                    .addKeyValue("verilog.eventType", "USER_LOGIN")
                    .log("User {} logged in", "alice");
            logger.atInfo()
                    .addKeyValue("verilog.eventType", "USER_LOGOUT")
                    .log("User {} logged out", "alice");
        } finally {
            appender.stop();
            context.stop();
        }

        if (!Files.isRegularFile(activeFile) || Files.size(activeFile) == 0) {
            throw new IllegalStateException("No VeriLog output was written");
        }
        DirectoryVerifyReport report = new VeriLogReader().verifyDirectory(logDir, dek, resolver);
        if (!report.allOk() || report.results().isEmpty()) {
            throw new IllegalStateException("VeriLog verification failed: " + failureReason(report));
        }
        long verifiedEntries = report.results().get(report.results().size() - 1).lastSeqOrFailSeq;
        if (verifiedEntries != 2) {
            throw new IllegalStateException("Expected two explicit audit entries; verified " + verifiedEntries);
        }

        System.out.println("VeriLog verification succeeded.");
        System.out.println("Verified audit entries: " + verifiedEntries);
    }

    private static String failureReason(DirectoryVerifyReport report) {
        return report.results().stream()
                .filter(result -> !result.ok)
                .map(result -> result.file + ": " + result.reason)
                .findFirst()
                .orElse("no .vlog files were verified");
    }
}
