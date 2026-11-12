package com.example.mobitive.cache;

import android.content.Context;
import android.util.Log;

import com.example.mobitive.analyzer.ApkAnalyzer;
import com.example.mobitive.analyzer.DexExtractor;
import com.example.mobitive.analyzer.ManifestExtractor;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Content-addressed cache of COMPLETED static feature extraction.
 *
 * The key includes SHA-256 of the ENTIRE input APK, the exact feature dictionary
 * bytes, and an explicit cache format version. No filename/URI/mtime shortcuts.
 * The prediction is never cached: every scan still invokes the current TFLite
 * classifier. Only app-private cache files are used; corrupt entries fall back
 * to a full fresh scan.
 */
public final class AnalysisCache {
    private static final String TAG = "MobiTiveCache";
    private static final int MAGIC = 0x4d334143; // M3AC
    // v2 (M5): API features come from DEX method_ids; v1 entries are ignored.
    private static final int VERSION = 2;
    private static final int MAX_VECTOR_SIZE = 100_000;
    private static final int MAX_SET_ENTRIES = 200000;
    private static final long MAX_CACHE_BYTES = 32L * 1024L * 1024L;
    private static final int MAX_ENTRIES = 8;
    private static final String PREFIX = "m3-v2-";

    private final File dir;
    private final String dictionarySha256;

    public AnalysisCache(Context context) throws IOException {
        this(new File(context.getApplicationContext().getCacheDir(), "m3-analysis-cache"),
                dictionaryDigest(context.getApplicationContext()));
    }

    /** @param dictionarySha256 SHA-256 of the feature dictionary the cached vectors were built with. */
    public AnalysisCache(File dir, String dictionarySha256) throws IOException {
        this.dir = dir;
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("Unable to create analysis cache");
        }
        if (dictionarySha256 == null || !dictionarySha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid dictionary SHA-256");
        }
        this.dictionarySha256 = dictionarySha256;
    }

    private static String dictionaryDigest(Context app) throws IOException {
        try (InputStream dictionary = app.getAssets().open("feature_dictionary.json")) {
            return digestStream(dictionary);
        }
    }

    public static String sha256(File file) throws IOException {
        if (file == null || !file.isFile() || file.length() <= 0) {
            throw new IOException("Cannot hash empty or missing APK");
        }
        try (InputStream input = new FileInputStream(file)) {
            return digestStream(input);
        }
    }

    private static String digestStream(InputStream input) throws IOException {
        final MessageDigest hash;
        try {
            hash = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        byte[] buffer = new byte[64 * 1024];
        int n;
        while ((n = input.read(buffer)) != -1) {
            hash.update(buffer, 0, n);
        }
        return toHex(hash.digest());
    }

    private static String toHex(byte[] bytes) {
        final char[] chars = "0123456789abcdef".toCharArray();
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[i * 2] = chars[(bytes[i] & 255) >>> 4];
            out[i * 2 + 1] = chars[bytes[i] & 15];
        }
        return new String(out);
    }

    private File target(String apkSha) {
        if (apkSha == null || !apkSha.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid APK SHA-256");
        }
        return new File(dir, PREFIX + dictionarySha256 + "-" + apkSha + ".bin");
    }

    /** Returns null for a cache miss or invalid entry, never a partial result. */
    public ApkAnalyzer.AnalysisResult load(String apkSha) {
        File source = target(apkSha);
        if (!source.isFile()) return null;
        if (source.length() > MAX_CACHE_BYTES || source.length() < 128) {
            deleteQuietly(source);
            return null;
        }
        try (DataInputStream input = new DataInputStream(
                new BufferedInputStream(new FileInputStream(source)))) {
            if (input.readInt() != MAGIC || input.readInt() != VERSION) {
                throw new IOException("Stale cache format");
            }
            if (!apkSha.equals(input.readUTF()) ||
                    !dictionarySha256.equals(input.readUTF())) {
                throw new IOException("Cache key mismatch");
            }
            int size = input.readInt();
            if (size <= 0 || size > MAX_VECTOR_SIZE) throw new IOException("Invalid vector shape");
            float[] vector = new float[size];
            int active = 0;
            for (int i = 0; i < size; i++) {
                float value = input.readFloat();
                if (value != 0f && value != 1f) {
                    throw new IOException("Non-binary cached vector");
                }
                vector[i] = value;
                if (value == 1f) active++;
            }
            int[] counters = new int[10];
            for (int i = 0; i < counters.length; i++) {
                counters[i] = input.readInt();
                if (counters[i] < 0 || counters[i] > 100000000) {
                    throw new IOException("Corrupt cache counters");
                }
            }
            if (counters[2] != active) throw new IOException("Active count mismatch");
            Set<String> permissions = readSet(input);
            Set<String> intents = readSet(input);
            Set<String> hardware = readSet(input);
            Map<String, Integer> calls = readCounts(input);
            ManifestExtractor.ManifestFeatures manifest =
                    new ManifestExtractor.ManifestFeatures(permissions, intents, hardware);
            DexExtractor.DexFeatures dex = new DexExtractor.DexFeatures(
                    calls.keySet(), calls,
                    counters[5], counters[6], counters[7], counters[8], counters[9]);
            if (calls.size() != counters[0] ||
                    manifest.toFeatureSet().size() != counters[1] ||
                    input.read() != -1) {
                throw new IOException("Corrupt cached feature counts/trailing bytes");
            }
            // Touch for approximate LRU eviction; if it fails, cache still valid.
            source.setLastModified(System.currentTimeMillis());
            return new ApkAnalyzer.AnalysisResult(vector,
                    counters[0], counters[1], counters[2], counters[3], counters[4],
                    counters[5], counters[6], counters[7], counters[8], counters[9],
                    manifest, dex);
        } catch (Exception e) {
            Log.w(TAG, "Ignoring invalid cache entry; full scan will be used", e);
            deleteQuietly(source);
            return null;
        }
    }

    /** Saves after successful classification only; failure must never fail a scan. */
    public void save(String apkSha, ApkAnalyzer.AnalysisResult result) throws IOException {
        File destination = target(apkSha);
        File tmp = File.createTempFile("m3_", ".tmp", dir);
        boolean committed = false;
        try {
            try (DataOutputStream out = new DataOutputStream(
                    new BufferedOutputStream(new FileOutputStream(tmp)))) {
                out.writeInt(MAGIC);
                out.writeInt(VERSION);
                out.writeUTF(apkSha);
                out.writeUTF(dictionarySha256);
                float[] vector = result.getFeatureVector();
                if (vector.length == 0 || vector.length > MAX_VECTOR_SIZE) {
                    throw new IOException("Invalid vector size");
                }
                out.writeInt(vector.length);
                for (float value : vector) {
                    if (value != 0f && value != 1f) throw new IOException("Non-binary vector");
                    out.writeFloat(value);
                }
                out.writeInt(result.getExtractedApiCount());
                out.writeInt(result.getExtractedManifestCount());
                out.writeInt(result.getActiveFeatureCount());
                out.writeInt(result.getUnknownApiCount());
                out.writeInt(result.getUnknownManifestCount());
                out.writeInt(result.getDexFileCount());
                out.writeInt(result.getClassDefCount());
                out.writeInt(result.getMethodRefCount());
                out.writeInt(result.getFrameworkMethodRefCount());
                out.writeInt(result.getBundledLibraryRefCount());
                ManifestExtractor.ManifestFeatures m = result.getManifest();
                writeSet(out, m.getPermissions());
                writeSet(out, m.getIntents());
                writeSet(out, m.getHardwareFeatures());
                writeCounts(out, result.getDex().getApiCallCount());
            }
            if (tmp.length() > MAX_CACHE_BYTES) {
                throw new IOException("Cache entry exceeds maximum size");
            }
            if (destination.exists() && !destination.delete()) {
                throw new IOException("Cannot replace old cache file");
            }
            if (!tmp.renameTo(destination)) {
                throw new IOException("Cannot commit cache file");
            }
            committed = true;
            evictOldEntries();
        } finally {
            if (!committed) deleteQuietly(tmp);
        }
    }

    private static Set<String> readSet(DataInputStream input) throws IOException {
        int n = boundedCount(input.readInt());
        Set<String> result = new HashSet<>();
        for (int i = 0; i < n; i++) {
            if (!result.add(input.readUTF())) throw new IOException("Duplicate cached set entry");
        }
        return result;
    }

    private static void writeSet(DataOutputStream out, Set<String> values) throws IOException {
        boundedCount(values.size());
        out.writeInt(values.size());
        for (String value : values) out.writeUTF(value);
    }

    private static Map<String, Integer> readCounts(DataInputStream input) throws IOException {
        int n = boundedCount(input.readInt());
        Map<String, Integer> result = new HashMap<>();
        for (int i = 0; i < n; i++) {
            String api = input.readUTF();
            int count = input.readInt();
            if (count <= 0 || result.put(api, count) != null) {
                throw new IOException("Invalid cached API counts");
            }
        }
        return result;
    }

    private static void writeCounts(DataOutputStream out, Map<String, Integer> values)
            throws IOException {
        boundedCount(values.size());
        out.writeInt(values.size());
        for (Map.Entry<String, Integer> entry : values.entrySet()) {
            out.writeUTF(entry.getKey());
            if (entry.getValue() == null || entry.getValue() <= 0) {
                throw new IOException("Invalid API occurrence count");
            }
            out.writeInt(entry.getValue());
        }
    }

    private static int boundedCount(int count) throws IOException {
        if (count < 0 || count > MAX_SET_ENTRIES) throw new IOException("Invalid list size");
        return count;
    }

    private void evictOldEntries() {
        File[] entries = dir.listFiles((folder, name) ->
                name.startsWith(PREFIX) && name.endsWith(".bin"));
        if (entries == null || entries.length <= MAX_ENTRIES) return;
        Arrays.sort(entries, Comparator.comparingLong(File::lastModified));
        for (int i = 0; i < entries.length - MAX_ENTRIES; i++) {
            deleteQuietly(entries[i]);
        }
    }

    private static void deleteQuietly(File file) {
        if (file != null && file.exists() && !file.delete()) {
            Log.w(TAG, "Could not delete cache entry: " + file.getName());
        }
    }
}
