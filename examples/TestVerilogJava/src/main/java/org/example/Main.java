package org.example;

import io.github.em.verilog.logger.VeriLogger;
import io.github.em.verilog.logger.VeriLoggerConfig;
import io.github.em.verilog.sign.BcEcdsaP256Signer;


import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

public class Main {

    private static byte[] loadDekFromEnv() {
        String hex = System.getenv("VERILOG_DEK_HEX");
        if (hex == null || hex.isBlank()) {
            throw new IllegalStateException("ENV VERILOG_DEK_HEX not set (64 hex chars für 32 bytes).");
        }
        byte[] dek;
        try {
            dek = HexFormat.of().parseHex(hex.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("VERILOG_DEK_HEX is no valid Hex.", e);
        }
        if (dek.length != 32) {
            throw new IllegalStateException("VERILOG_DEK_HEX must be 32 bytes (64 hex chars) but is: " + dek.length);
        }
        return dek;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("ENV visible: " + System.getenv("VERILOG_DEK_HEX"));
        // 1) DEK from ENV (fixed key for Writer + Reader)
        byte[] dek = loadDekFromEnv();

        // 2) (Demo) Create ECDSA KeyPair
        Path keyDir = Path.of("demo-keys");
        KeyPair kp = loadOrCreateSigner(keyDir);

        var signer = new BcEcdsaP256Signer(
                kp.getPrivate().getEncoded(),
                kp.getPublic().getEncoded(),
                true
        );


        VeriLoggerConfig cfg = new VeriLoggerConfig();
        cfg.logDir = Path.of("demo-logs");
        cfg.filePrefix = "demo";
        cfg.currentFileName = "current.vlog";
        cfg.aadPrefix = "VeriLog|v1";
        cfg.encryptionKey32 = dek;

        cfg.actor = "demo-app";
        cfg.signer = signer;

        cfg.rotateOnStartup = true;
        cfg.flushEveryN = 50;

        cfg.validate();

        try (VeriLogger logger = VeriLogger.create(cfg)) {
            logger.info("System started");
            logger.warn("Warning: Testevent");
            logger.error("Error: Testevent");
        }

        System.out.println("OK. Logs under: " + cfg.logDir.toAbsolutePath());
    }



    static KeyPair loadOrCreateSigner(Path dir) throws Exception {
        Files.createDirectories(dir);

        Path privPath = dir.resolve("signer_priv.pkcs8");
        Path pubPath  = dir.resolve("signer_pub.spki");

        KeyFactory kf = KeyFactory.getInstance("EC");

        if (Files.exists(privPath) && Files.exists(pubPath)) {
            PrivateKey priv = kf.generatePrivate(
                    new PKCS8EncodedKeySpec(Files.readAllBytes(privPath))
            );

            PublicKey pub = kf.generatePublic(
                    new X509EncodedKeySpec(Files.readAllBytes(pubPath))
            );

            return new KeyPair(pub, priv);
        }

        // Falls nicht vorhanden → neu erzeugen
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();

        Files.write(privPath, kp.getPrivate().getEncoded(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);

        Files.write(pubPath, kp.getPublic().getEncoded(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);

        return kp;
    }
}