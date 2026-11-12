package com.example.mobitive;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.example.mobitive.analyzer.ManifestExtractor;
import com.example.mobitive.ml.FeatureDictionary;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class ManifestFeatureContractTest {
    @Test
    public void hardwareFeatureUsesTrainingPrefix() {
        Set<String> hardware = new HashSet<>();
        hardware.add("android.hardware.camera");

        ManifestExtractor.ManifestFeatures m = new ManifestExtractor.ManifestFeatures(
                Collections.emptySet(), Collections.emptySet(), hardware);

        assertTrue(m.toFeatureSet().contains("hardware:android.hardware.camera"));
        assertFalse(m.toFeatureSet().contains("feature:android.hardware.camera"));
    }

    @Test
    public void dictionaryHasExpectedManifestHardwareFeatures() throws Exception {
        FeatureDictionary dictionary = FeatureDictionary.load(
                InstrumentationRegistry.getInstrumentation().getTargetContext());
        assertEquals(2915, dictionary.getFeatureCount());

        int hardwareCount = 0;
        for (String name : dictionary.getManifestFeatures()) {
            if (name.startsWith("hardware:")) {
                assertTrue(dictionary.getManifestIndex(name) >= 0);
                hardwareCount++;
            }
        }
        assertTrue("Missing hardware: features from training dictionary", hardwareCount > 0);
    }
}
