/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.cli;

import io.github.em.verilog.errors.VeriLogFormatException;
import io.github.em.verilog.reader.*;
import io.github.em.verilog.sign.BcPemKeys;
import io.github.em.verilog.sign.BcPublicKeyLoader;
import io.github.em.verilog.CryptoUtil;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.nio.file.*;
import java.util.*;

public final class VerifyCommand {

    /**
     * Exit codes:
     * 0 = OK
     * 2 = verification failed
     * 3 = bad arguments
     * 4 = I/O or unexpected errors
     */
    public int run(String[] args) {
        if (!isVerifyCommand(args)) {
            printHelp();
            return 3;
        }

        try {
            Map<String, String> flags = parseFlags(Arrays.copyOfRange(args, 1, args.length));
            RunConfig cfg = parseAndValidate(flags);
            return executeVerify(cfg);
        } catch (IllegalArgumentException e) {
            System.err.println("ERROR: " + e.getMessage());
            return 3;
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return 4;
        }
    }

    private static boolean isVerifyCommand(String[] args) {
        return args != null
                && args.length > 0
                && "verify".equalsIgnoreCase(args[0]);
    }

    private static final class RunConfig {
        final Path dir;
        final Path file;
        final byte[] dek32;
        final PublicKeyResolver resolver;
        final boolean stopOnFirstFailure;
        final boolean toleratePartial;

        RunConfig(Path dir,
                  Path file,
                  byte[] dek32,
                  PublicKeyResolver resolver,
                  boolean stopOnFirstFailure,
                  boolean toleratePartial) {
            this.dir = dir;
            this.file = file;
            this.dek32 = dek32;
            this.resolver = resolver;
            this.stopOnFirstFailure = stopOnFirstFailure;
            this.toleratePartial = toleratePartial;
        }
    }

    private RunConfig parseAndValidate(Map<String, String> flags) throws Exception {
        Path dir = flags.containsKey("dir") ? java.nio.file.Paths.get(flags.get("dir")) : null;
        Path file = flags.containsKey("file") ? java.nio.file.Paths.get(flags.get("file")) : null;

        if (!exactlyOneProvided(dir, file)) {
            System.err.println("ERROR: Provide exactly one of --dir or --file.");
            printHelpVerify();
            throw new IllegalArgumentException("invalid input"); // triggers exit code 3 as before
        }

        byte[] dek32 = DekParser.parseDek(flags);
        if (dek32 == null) {
            throw new IllegalArgumentException(
                    "Provide --dek-hex (64 hex chars) or --dek-b64 (base64 of 32 bytes)."
            );
        }

        List<Path> pubPaths = parsePubPaths(flags.get("pub"));
        if (pubPaths.isEmpty()) {
            throw new IllegalArgumentException("Provide at least one --pub <publicKeyPemPath>.");
        }

        PublicKeyResolver resolver = loadKeys(pubPaths);

        boolean stopOnFirstFailure =
                !"false".equalsIgnoreCase(flags.getOrDefault("stop-on-fail", "true"));

        boolean toleratePartial =
                "true".equalsIgnoreCase(flags.getOrDefault("tolerate-partial", "false"));

        return new RunConfig(dir, file, dek32, resolver, stopOnFirstFailure, toleratePartial);
    }

    private static boolean exactlyOneProvided(Path a, Path b) {
        return (a == null) ^ (b == null);
    }

    private static List<Path> parsePubPaths(String pubFlag) {
        List<Path> pubPaths = new ArrayList<>();
        if (pubFlag == null) return pubPaths;

        for (String p : pubFlag.split(",")) {
            if (p != null) {
                String t = p.trim();
                if (!t.isEmpty()) pubPaths.add(java.nio.file.Paths.get(t));
            }
        }
        return pubPaths;
    }

    private int executeVerify(RunConfig cfg) throws Exception {
        VeriLogReader reader = new VeriLogReader();

        if (cfg.file != null) {
            VerifyReport rep = reader.verifyFile(cfg.file, cfg.dek32, cfg.resolver, cfg.toleratePartial);
            printFileResult(cfg.file, rep.valid, rep.seq, rep.reason);
            return rep.valid ? 0 : 2;
        }

        DirectoryVerifyReport dr = reader.verifyDirectory(cfg.dir, cfg.dek32, cfg.resolver, cfg.stopOnFirstFailure);
        boolean allOk = printDirectoryResults(dr);
        System.out.println(allOk ? "ALL FILES OK" : "SOME FILES FAILED");
        return allOk ? 0 : 2;
    }

    private boolean printDirectoryResults(DirectoryVerifyReport dr) {
        boolean allOk = true;
        for (var r : dr.results()) { // if Java 8, replace 'var' with explicit type
            printFileResult(r.file, r.ok, r.lastSeqOrFailSeq, r.reason);
            if (!r.ok) allOk = false;
        }
        return allOk;
    }

    private static void printFileResult(Path file, boolean ok, long seq, String reason) {
        String name = file.getFileName().toString();
        if (ok) {
            System.out.println(name + " -> OK (lastSeq=" + seq + ")");
        } else {
            System.out.println(name + " -> FAIL (seq=" + seq + "): " + reason);
        }
    }

    private static PublicKeyResolver loadKeys(List<Path> pubPemPaths) throws Exception {
        Map<String, ECPublicKeyParameters> map = new HashMap<>();

        for (Path p : pubPemPaths) {
            String pem = Files.readString(p);
            byte[] spkiDer = BcPemKeys.readSpkiPublicKeyDer(pem);
            ECPublicKeyParameters pub = BcPublicKeyLoader.fromSpkiDer(spkiDer);

            String keyId = CryptoUtil.toHexLower(CryptoUtil.sha256(spkiDer));
            map.put(keyId, pub);
        }

        return new MapPublicKeyResolver(map);
    }

    private static Map<String, String> parseFlags(String[] args) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (!a.startsWith("--")) throw new IllegalArgumentException("Unexpected arg: " + a);

            String key = a.substring(2);
            String val = "true";

            // flags with values
            if (key.equals("dir") || key.equals("file") || key.equals("dek-hex") || key.equals("dek-b64") || key.equals("pub")
                    || key.equals("stop-on-fail") || key.equals("tolerate-partial")) {
                if (i + 1 >= args.length) throw new IllegalArgumentException("Missing value for --" + key);
                val = args[++i];
            }

            m.put(key, val);
        }
        return m;
    }

    private static void printHelp() {
        System.out.println("Usage:");
        printHelpVerify();
    }

    private static void printHelpVerify() {
        System.out.println("  verilog verify --dir <logDir> --dek-hex <64hex> --pub <pub.pem>[,<pub2.pem>...] [--stop-on-fail true|false]");
        System.out.println("  verilog verify --file <file.vlog> --dek-hex <64hex> --pub <pub.pem> [--tolerate-partial true|false]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --dir                Directory containing .vlog files");
        System.out.println("  --file               Single .vlog file");
        System.out.println("  --dek-hex            32-byte DEK as 64 hex chars");
        System.out.println("  --dek-b64            32-byte DEK as base64");
        System.out.println("  --pub                Public key PEM path(s), comma-separated allowed");
        System.out.println("  --stop-on-fail       For --dir: stop at first failed file (default true)");
        System.out.println("  --tolerate-partial   For --file: ignore trailing partial frame (default false)");
    }
}