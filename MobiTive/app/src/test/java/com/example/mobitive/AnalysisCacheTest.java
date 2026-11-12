package com.example.mobitive;

import com.example.mobitive.analyzer.ApkAnalyzer;
import com.example.mobitive.analyzer.DexExtractor;
import com.example.mobitive.analyzer.ManifestExtractor;
import com.example.mobitive.cache.AnalysisCache;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class AnalysisCacheTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static final String DICT_A = repeat('a');
    private static final String DICT_B = repeat('b');

    private static String repeat(char c) {
        char[] chars = new char[64];
        Arrays.fill(chars, c);
        return new String(chars);
    }

    private static String apkSha(int i) {
        return String.format("%064x", i);
    }

    /** A consistent result: counters match the vector and the feature sets. */
    private static ApkAnalyzer.AnalysisResult sample() {
        float[] vector = {1f, 0f, 1f, 0f, 1f, 0f};
        Set<String> permissions = new HashSet<>(Arrays.asList("android.permission.SEND_SMS"));
        Set<String> intents = new HashSet<>(Arrays.asList("android.intent.action.BOOT_COMPLETED"));
        Set<String> hardware = new HashSet<>();
        ManifestExtractor.ManifestFeatures manifest =
                new ManifestExtractor.ManifestFeatures(permissions, intents, hardware);
        Map<String, Integer> calls = new HashMap<>();
        calls.put("Landroid/telephony/SmsManager;->sendTextMessage()V", 1);
        calls.put("Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;", 2);
        DexExtractor.DexFeatures dex = new DexExtractor.DexFeatures(
                calls.keySet(), calls, 2, 10, 300, 120, 4);
        return new ApkAnalyzer.AnalysisResult(vector, calls.size(), manifest.toFeatureSet().size(),
                3, 0, 0, 2, 10, 300, 120, 4, manifest, dex);
    }

    @Test
    public void roundTripRestoresEverything() throws IOException {
        AnalysisCache cache = new AnalysisCache(tmp.newFolder(), DICT_A);
        ApkAnalyzer.AnalysisResult original = sample();
        cache.save(apkSha(1), original);

        ApkAnalyzer.AnalysisResult loaded = cache.load(apkSha(1));

        assertNotNull(loaded);
        assertArrayEquals(original.getFeatureVector(), loaded.getFeatureVector(), 0f);
        assertEquals(original.getActiveFeatureCount(), loaded.getActiveFeatureCount());
        assertEquals(original.getMethodRefCount(), loaded.getMethodRefCount());
        assertEquals(original.getDex().getApiCalls(), loaded.getDex().getApiCalls());
        assertEquals(original.getManifest().toFeatureSet(), loaded.getManifest().toFeatureSet());
    }

    @Test
    public void missForUnknownApk() throws IOException {
        AnalysisCache cache = new AnalysisCache(tmp.newFolder(), DICT_A);
        assertNull(cache.load(apkSha(42)));
    }

    @Test
    public void differentDictionaryNeverHits() throws IOException {
        File dir = tmp.newFolder();
        new AnalysisCache(dir, DICT_A).save(apkSha(1), sample());
        assertNull("vector built with another dictionary must not be reused",
                new AnalysisCache(dir, DICT_B).load(apkSha(1)));
    }

    @Test
    public void corruptedEntryIsMissAndDeleted() throws IOException {
        File dir = tmp.newFolder();
        AnalysisCache cache = new AnalysisCache(dir, DICT_A);
        cache.save(apkSha(1), sample());
        File entry = dir.listFiles((d, name) -> name.endsWith(".bin"))[0];
        try (RandomAccessFile f = new RandomAccessFile(entry, "rw")) {
            f.seek(entry.length() / 2);
            f.write(0x7F); // flip bytes in the middle
            f.write(0x7F);
        }
        assertNull(cache.load(apkSha(1)));
        assertFalse("corrupt entry should be removed", entry.exists());
    }

    @Test
    public void evictsOldestBeyondEightEntries() throws IOException {
        File dir = tmp.newFolder();
        AnalysisCache cache = new AnalysisCache(dir, DICT_A);
        for (int i = 0; i < 10; i++) {
            cache.save(apkSha(i), sample());
            File[] all = dir.listFiles((d, name) -> name.endsWith(".bin"));
            for (File f : all) {   // make modification order deterministic
                if (f.getName().endsWith(apkSha(i) + ".bin")) f.setLastModified(1_000_000L + i * 1000L);
            }
        }
        assertEquals(8, dir.listFiles((d, name) -> name.endsWith(".bin")).length);
        assertNotNull(cache.load(apkSha(9)));
        assertTrue(cache.load(apkSha(0)) == null || cache.load(apkSha(1)) == null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsNonHexKey() throws IOException {
        new AnalysisCache(tmp.newFolder(), DICT_A).load("../../etc/passwd");
    }
}
