package com.example.mobitive;

import com.example.mobitive.ml.FeatureDictionary;
import com.example.mobitive.ml.FeatureVectorizer;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class FeatureVectorizerTest {

    private static final FeatureDictionary DICT = FeatureDictionary.fromLists(
            Arrays.asList("Landroid/telephony/SmsManager;->sendTextMessage()V",
                    "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"),
            Arrays.asList("permission:android.permission.SEND_SMS",
                    "intent:android.intent.action.BOOT_COMPLETED",
                    "hardware:android.hardware.camera"));

    @Test
    public void layoutIsApiFirstThenManifest() {
        assertEquals(5, DICT.getFeatureCount());
        assertEquals(0, DICT.getApiIndex("Landroid/telephony/SmsManager;->sendTextMessage()V"));
        assertEquals(2, DICT.getManifestIndex("permission:android.permission.SEND_SMS"));
        assertEquals(4, DICT.getManifestIndex("hardware:android.hardware.camera"));
        assertEquals(-1, DICT.getApiIndex("permission:android.permission.SEND_SMS"));
    }

    @Test
    public void binaryPresenceAndUnknownFeaturesIgnored() {
        FeatureVectorizer v = new FeatureVectorizer(DICT);
        Set<String> api = new HashSet<>(Arrays.asList(
                "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
                "Lcom/unknown/Foo;->bar()V"));
        Set<String> manifest = new HashSet<>(Arrays.asList(
                "hardware:android.hardware.camera",
                "permission:android.permission.UNKNOWN"));

        float[] vector = v.vectorize(api, manifest);

        assertArrayEquals(new float[]{0f, 1f, 0f, 0f, 1f}, vector, 0f);
        assertEquals(2, v.countActiveFeatures(vector));
    }

    @Test
    public void apiStringNeverMatchesManifestSlotAndViceVersa() {
        FeatureVectorizer v = new FeatureVectorizer(DICT);
        float[] vector = v.vectorize(
                Collections.singleton("permission:android.permission.SEND_SMS"),
                Collections.singleton("Landroid/telephony/SmsManager;->sendTextMessage()V"));
        assertEquals(0, v.countActiveFeatures(vector));
    }

    @Test
    public void nullSetsGiveZeroVector() {
        FeatureVectorizer v = new FeatureVectorizer(DICT);
        assertArrayEquals(new float[5], v.vectorize(null, null), 0f);
    }

    @Test(expected = IllegalStateException.class)
    public void duplicateFeaturesRejected() {
        FeatureDictionary.fromLists(Arrays.asList("a", "a"), Collections.emptyList());
    }
}
