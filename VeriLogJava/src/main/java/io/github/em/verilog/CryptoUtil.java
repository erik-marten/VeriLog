/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class CryptoUtil {
    private CryptoUtil() {
    }

    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sha256Utf8(String s) {
        return sha256(s.getBytes(StandardCharsets.UTF_8));
    }

    public static String toHexLower(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        if (hex == null) throw new NullPointerException("hex");
        String s = hex.trim();

        if ((s.length() % 2) != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        int len = s.length() / 2;
        byte[] out = new byte[len];

        for (int i = 0; i < len; i++) {
            int hi = hexCharToInt(s.charAt(2 * i));
            int lo = hexCharToInt(s.charAt(2 * i + 1));
            out[i] = (byte) ((hi << 4) | lo);
        }

        return out;
    }

    private static int hexCharToInt(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        throw new IllegalArgumentException("Invalid hex character: " + c);
    }
}