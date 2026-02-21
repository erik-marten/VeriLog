package org.example;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Set;

public class GenerateDek {

    public static void main(String[] args) throws Exception {
        // Defaults
        Path outDir = Path.of("demo-keys");
        boolean writeFiles = true;        // write files in outDir
        boolean alsoSigner = true;        // create additional signer keys
        boolean printDekHex = true;       // print DEK hex for ENV

        // --out demo-keys --no-files --no-signer --quiet
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--out" -> outDir = Path.of(args[++i]);
                case "--no-files" -> writeFiles = false;
                case "--no-signer" -> alsoSigner = false;
                case "--quiet" -> printDekHex = false;
                default -> throw new IllegalArgumentException("Unknown arg: " + args[i]);
            }
        }

        Files.createDirectories(outDir);

        // 1) create DEK
        byte[] dek = new byte[32];
        new SecureRandom().nextBytes(dek);
        String dekHex = HexFormat.of().formatHex(dek);

        if (printDekHex) {
            System.out.println("VERILOG_DEK_HEX=" + dekHex);
        }

        if (writeFiles) {
            // a) as raw 32 bytes
            Path dekBin = outDir.resolve("dek.bin");
            atomicWrite(dekBin, dek);

            // b) as hex text (Copy/Paste)
            Path dekHexFile = outDir.resolve("dek.hex");
            atomicWrite(dekHexFile, (dekHex + "\n").getBytes(StandardCharsets.UTF_8));

            lockDownPermissions(dekBin);
            lockDownPermissions(dekHexFile);
        }

        // 2) Create signer Keys (optional, but useful for Verify/Reader)
        if (alsoSigner) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();

            byte[] privPkcs8 = kp.getPrivate().getEncoded();
            byte[] pubSpki = kp.getPublic().getEncoded();

            if (writeFiles) {
                Path privPath = outDir.resolve("signer_priv.pkcs8");
                Path pubPath  = outDir.resolve("signer_pub.spki");

                atomicWrite(privPath, privPkcs8);
                atomicWrite(pubPath, pubSpki);

                lockDownPermissions(privPath);
                lockDownPermissions(pubPath);
            }

            System.out.println("Signer keys generated (P-256). Public key: " + outDir.resolve("signer_pub.spki"));
        }

        System.out.println("Done. Output dir: " + outDir.toAbsolutePath());
    }

    private static void atomicWrite(Path path, byte[] data) throws Exception {
        Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
        Files.write(tmp, data, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        try {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void lockDownPermissions(Path path) {
        try {
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(path, perms);
        } catch (Exception ignored) {}
    }
}