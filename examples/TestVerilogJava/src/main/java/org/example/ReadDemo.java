package org.example;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.em.verilog.CryptoUtil;
import io.github.em.verilog.crypto.XChaCha20Poly1305;
import io.github.em.verilog.reader.*;

import io.github.em.verilog.sign.BcPublicKeyLoader;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Map;

public class ReadDemo {

    private static byte[] loadDekFromEnv() {
        String hex = System.getenv("VERILOG_DEK_HEX");
        if (hex == null || hex.isBlank()) {
            throw new IllegalStateException("ENV VERILOG_DEK_HEX not set (64 hex chars für 32 bytes).");
        }
        byte[] dek = HexFormat.of().parseHex(hex.trim());
        if (dek.length != 32) throw new IllegalStateException("DEK must be 32 bytes but is: " + dek.length);
        return dek;
    }

    private static byte[] buildAad(byte[] prefix, byte type, long seq) {
        // aad = prefix || 0x00 || uint64_be(seq) || 0x00 || type
        ByteBuffer bb = ByteBuffer
                .allocate(prefix.length + 1 + 8 + 1 + 1)
                .order(ByteOrder.BIG_ENDIAN);

        bb.put(prefix);
        bb.put((byte) 0x00);
        bb.putLong(seq);
        bb.put((byte) 0x00);
        bb.put(type);
        return bb.array();
    }

    public static void main(String[] args) throws Exception {
        Path vlog = Path.of("demo-logs/current.vlog");
        Path spkiPath = Path.of("demo-keys/signer_pub.spki");

        byte[] dek32 = loadDekFromEnv();
        byte[] spkiDer = Files.readAllBytes(spkiPath);

        String keyIdHex = CryptoUtil.toHexLower(CryptoUtil.sha256(spkiDer));
        ECPublicKeyParameters pub = BcPublicKeyLoader.fromSpkiDer(spkiDer);

        PublicKeyResolver resolver = new MapPublicKeyResolver(Map.of(keyIdHex, pub));

        // 1) Verify (Signatur + Hashchain + AEAD)
        VeriLogReader reader = new VeriLogReader();
        VerifyReport rep = reader.verifyFile(vlog, dek32, resolver);
        System.out.println("VERIFY ok=" + rep.ok + " lastOkSeq=" + rep.seq + " error=" + rep.reason);

        // 2) Optional: Frames decryption and print JSON
        ObjectMapper om = new ObjectMapper();

        try (FramedFileReader r = new FramedFileReader(vlog)) {

            String headerJson = new String(r.rawHeaderJsonBytes(), StandardCharsets.UTF_8);
            JsonNode header = om.readTree(headerJson);

            String aadPrefix = header.has("aad") ? header.get("aad").asText() : "VeriLog|v1";
            byte[] aadPrefixBytes = aadPrefix.getBytes(StandardCharsets.UTF_8);

            r.positionAtFirstFrame();

            while (true) {
                Frame f = r.readNextFrame(true);
                if (f == null) break;

                byte[] aad = buildAad(aadPrefixBytes, f.type, f.seq);
                byte[] plaintext = XChaCha20Poly1305.decrypt(dek32, f.nonce24, f.ct, aad);

                JsonNode signed = om.readTree(new String(plaintext, StandardCharsets.UTF_8));

                String ts = signed.path("ts").asText();
                String actor = signed.path("actor").asText();
                String eventType = signed.path("eventType").asText();

                JsonNode event = signed.path("event");
                String msg = event.path("msg").asText();

                System.out.println("SEQ=" + f.seq + " TS=" + ts + " ACTOR=" + actor + " LEVEL=" + eventType);
                System.out.println("MSG=" + msg);

                // optional: fields
                JsonNode fields = event.path("fields");
                if (!fields.isMissingNode() && fields.size() > 0) {
                    System.out.println("FIELDS=" + fields.toString());
                }
                System.out.println("----");
            }
        }
    }
}