package io.github.em.verilog.cli;

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
     * 4 = I/O or unexpected error
     */
    public int run(String[] args) {
        if (args == null || args.length == 0) {
            printHelp();
            return 3;
        }

        if (!"verify".equalsIgnoreCase(args[0])) {
            printHelp();
            return 3;
        }

        try {
            Map<String, String> flags = parseFlags(Arrays.copyOfRange(args, 1, args.length));

            Path dir = null;
            Path file = null;

            if (flags.containsKey("dir")) dir = Path.of(flags.get("dir"));
            if (flags.containsKey("file")) file = Path.of(flags.get("file"));

            if ((dir == null && file == null) || (dir != null && file != null)) {
                System.err.println("ERROR: Provide exactly one of --dir or --file.");
                printHelpVerify();
                return 3;
            }

            byte[] dek32 = DekParser.parseDek(flags);
            if (dek32 == null) {
                System.err.println("ERROR: Provide --dek-hex (64 hex chars) or --dek-b64 (base64 of 32 bytes).");
                return 3;
            }

            List<Path> pubPaths = new ArrayList<>();
            if (flags.containsKey("pub")) {
                // allow comma-separated
                for (String p : flags.get("pub").split(",")) {
                    if (!p.isBlank()) pubPaths.add(Path.of(p.trim()));
                }
            }
            if (pubPaths.isEmpty()) {
                System.err.println("ERROR: Provide at least one --pub <publicKeyPemPath>.");
                return 3;
            }

            PublicKeyResolver resolver = loadKeys(pubPaths);

            VeriLogReader reader = new VeriLogReader();

            boolean stopOnFirstFailure = !"false".equalsIgnoreCase(flags.getOrDefault("stop-on-fail", "true"));

            if (file != null) {
                boolean tolerate = "true".equalsIgnoreCase(flags.getOrDefault("tolerate-partial", "false"));
                VerifyReport rep = reader.verifyFile(file, dek32, resolver, tolerate);
                printFileResult(file, rep.ok, rep.seq, rep.reason);
                return rep.ok ? 0 : 2;
            } else {
                DirectoryVerifyReport dr = reader.verifyDirectory(dir, dek32, resolver, stopOnFirstFailure);
                boolean allOk = true;
                for (var r : dr.results()) {
                    printFileResult(r.file, r.ok, r.lastSeqOrFailSeq, r.reason);
                    if (!r.ok) allOk = false;
                }
                System.out.println(allOk ? "ALL FILES OK" : "SOME FILES FAILED");
                return allOk ? 0 : 2;
            }

        } catch (IllegalArgumentException e) {
            System.err.println("ERROR: " + e.getMessage());
            return 3;
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return 4;
        }
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