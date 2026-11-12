package com.example.mobitive.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class HashUtils {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private HashUtils() { }

    public static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[i * 2] = HEX[(bytes[i] & 0xFF) >>> 4];
            out[i * 2 + 1] = HEX[bytes[i] & 0x0F];
        }
        return new String(out);
    }
}
