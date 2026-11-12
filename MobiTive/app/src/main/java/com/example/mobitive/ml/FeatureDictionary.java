
package com.example.mobitive.ml;

import android.content.Context;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class FeatureDictionary {

    private static final String ASSET_PATH = "feature_dictionary.json";

    private final List<String> apiFeatures;
    private final List<String> manifestFeatures;

    // Feature -> vị trí trong vector đặc trưng (API trước, Manifest sau)
    private final Map<String, Integer> apiIndexMap;
    private final Map<String, Integer> manifestIndexMap;

    private final int totalFeatureCount;

    private FeatureDictionary(
            List<String> apiFeatures,
            List<String> manifestFeatures
    ) {
        this.apiFeatures = Collections.unmodifiableList(
                new ArrayList<>(apiFeatures)
        );

        this.manifestFeatures = Collections.unmodifiableList(
                new ArrayList<>(manifestFeatures)
        );

        this.apiIndexMap = new LinkedHashMap<>();
        this.manifestIndexMap = new LinkedHashMap<>();

        // API features nằm ở đầu vector: index 0 -> 2289
        for (int i = 0; i < this.apiFeatures.size(); i++) {
            String feature = this.apiFeatures.get(i);

            if (apiIndexMap.put(feature, i) != null) {
                throw new IllegalStateException(
                        "Duplicate API feature: " + feature
                );
            }
        }

        // Manifest features nằm tiếp theo: index 2290 -> 2914
        int manifestOffset = this.apiFeatures.size();

        for (int i = 0; i < this.manifestFeatures.size(); i++) {
            String feature = this.manifestFeatures.get(i);

            if (manifestIndexMap.put(
                    feature,
                    manifestOffset + i
            ) != null) {
                throw new IllegalStateException(
                        "Duplicate Manifest feature: " + feature
                );
            }
        }

        totalFeatureCount =
                this.apiFeatures.size() + this.manifestFeatures.size();
    }

    /** Builds a dictionary directly (unit tests, tools). Index order = list order. */
    public static FeatureDictionary fromLists(List<String> apiFeatures, List<String> manifestFeatures) {
        return new FeatureDictionary(apiFeatures, manifestFeatures);
    }

    public static FeatureDictionary load(Context context)
            throws IOException {

        try (InputStream inputStream =
                     context.getAssets().open(ASSET_PATH);
             InputStreamReader reader =
                     new InputStreamReader(
                             inputStream,
                             StandardCharsets.UTF_8
                     )) {

            JsonObject root = JsonParser.parseReader(reader)
                    .getAsJsonObject();

            String representation =
                    root.get("representation").getAsString();

            if (!"binary_presence".equals(representation)) {
                throw new IllegalStateException(
                        "Unsupported representation: " + representation
                );
            }

            List<String> apiFeatures = readStringArray(
                    root.getAsJsonArray("api_features")
            );

            List<String> manifestFeatures = readStringArray(
                    root.getAsJsonArray("manifest_features")
            );

            int expectedApiCount =
                    root.get("api_feature_count").getAsInt();

            int expectedManifestCount =
                    root.get("manifest_feature_count").getAsInt();

            int expectedTotalCount =
                    root.get("total_feature_count").getAsInt();

            if (apiFeatures.size() != expectedApiCount) {
                throw new IllegalStateException(
                        "API feature count mismatch."
                );
            }

            if (manifestFeatures.size() != expectedManifestCount) {
                throw new IllegalStateException(
                        "Manifest feature count mismatch."
                );
            }

            if (apiFeatures.size() + manifestFeatures.size()
                    != expectedTotalCount) {
                throw new IllegalStateException(
                        "Total feature count mismatch."
                );
            }

            return new FeatureDictionary(
                    apiFeatures,
                    manifestFeatures
            );
        }
    }

    private static List<String> readStringArray(JsonArray array) {

        if (array == null) {
            throw new IllegalStateException(
                    "Missing feature array in JSON."
            );
        }

        List<String> result = new ArrayList<>();

        for (int i = 0; i < array.size(); i++) {
            result.add(array.get(i).getAsString());
        }

        return result;
    }

    public int getApiIndex(String feature) {
        Integer index = apiIndexMap.get(feature);
        return index == null ? -1 : index;
    }

    public int getManifestIndex(String feature) {
        Integer index = manifestIndexMap.get(feature);
        return index == null ? -1 : index;
    }

    public int getFeatureCount() {
        return totalFeatureCount;
    }

    public int getApiFeatureCount() {
        return apiFeatures.size();
    }

    public int getManifestFeatureCount() {
        return manifestFeatures.size();
    }

    public List<String> getApiFeatures() {
        return apiFeatures;
    }

    public List<String> getManifestFeatures() {
        return manifestFeatures;
    }
}
