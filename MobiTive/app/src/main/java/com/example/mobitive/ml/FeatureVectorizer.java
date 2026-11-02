
package com.example.mobitive.ml;

import java.util.Set;

public class FeatureVectorizer {

    private final FeatureDictionary dictionary;

    public FeatureVectorizer(FeatureDictionary dictionary) {

        if (dictionary == null) {
            throw new IllegalArgumentException(
                    "FeatureDictionary cannot be null."
            );
        }

        this.dictionary = dictionary;
    }

    /**
     * Chuyển các API và Manifest features thành vector nhị phân.
     *
     * @param apiCalls Các API descriptor trích xuất từ DEX.
     * @param manifestFeatures Các feature trích xuất từ Manifest.
     * @return Vector float có 2915 phần tử.
     */
    public float[] vectorize(
            Set<String> apiCalls,
            Set<String> manifestFeatures
    ) {

        int featureCount = dictionary.getFeatureCount();

        float[] vector = new float[featureCount];

        // Đánh dấu API features
        if (apiCalls != null) {

            for (String feature : apiCalls) {

                int index = dictionary.getApiIndex(feature);

                if (index >= 0) {
                    vector[index] = 1.0f;
                }
            }
        }

        // Đánh dấu Manifest features
        if (manifestFeatures != null) {

            for (String feature : manifestFeatures) {

                int index = dictionary.getManifestIndex(feature);

                if (index >= 0) {
                    vector[index] = 1.0f;
                }
            }
        }

        return vector;
    }

    /**
     * Đếm số feature đã được nhận diện trong vector.
     */
    public int countActiveFeatures(float[] vector) {

        if (vector == null
                || vector.length != dictionary.getFeatureCount()) {
            throw new IllegalArgumentException(
                    "Invalid feature vector."
            );
        }

        int count = 0;

        for (float value : vector) {
            if (value == 1.0f) {
                count++;
            }
        }

        return count;
    }
}
