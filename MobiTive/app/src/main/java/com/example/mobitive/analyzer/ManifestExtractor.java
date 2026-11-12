
package com.example.mobitive.analyzer;

import android.util.Xml;

import net.dongliu.apk.parser.ApkParsers;

import org.xmlpull.v1.XmlPullParser;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class ManifestExtractor {

    private static final String ANDROID_NS =
            "http://schemas.android.com/apk/res/android";

    private static final Set<String> COMPONENT_TAGS = new HashSet<>();

    static {
        COMPONENT_TAGS.add("activity");
        COMPONENT_TAGS.add("activity-alias");
        COMPONENT_TAGS.add("service");
        COMPONENT_TAGS.add("receiver");
    }

    /**
     * Trích xuất ba nhóm đặc trưng:
     * 1. Permissions
     * 2. Intents (actions và categories)
     * 3. Hardware features
     */
    public ManifestFeatures extract(File apkFile)
            throws IOException, Exception {

        if (apkFile == null || !apkFile.exists()) {
            throw new IOException("APK file không tồn tại.");
        }

        // Đọc AndroidManifest.xml và chuyển binary XML thành XML text.
        String manifestXml = ApkParsers.getManifestXml(apkFile);

        if (manifestXml == null || manifestXml.trim().isEmpty()) {
            throw new IOException("Không đọc được AndroidManifest.xml");
        }

        Set<String> permissions = new HashSet<>();
        Set<String> intents = new HashSet<>();
        Set<String> hardwareFeatures = new HashSet<>();

        XmlPullParser parser = Xml.newPullParser();
        parser.setInput(
                new java.io.StringReader(manifestXml)
        );

        int componentDepth = -1;
        int intentFilterDepth = -1;

        int eventType = parser.getEventType();

        while (eventType != XmlPullParser.END_DOCUMENT) {

            if (eventType == XmlPullParser.START_TAG) {

                String tagName = parser.getName();
                int depth = parser.getDepth();

                // ---------------------------------
                // 1. Permissions
                // ---------------------------------

                if (tagName.equals("uses-permission")) {
                    String name = parser.getAttributeValue(
                            ANDROID_NS, "name"
                    );

                    if (name != null && !name.isEmpty()) {
                        permissions.add(name);
                    }
                }

                // ---------------------------------
                // 2. Intents
                // ---------------------------------

                if (COMPONENT_TAGS.contains(tagName)) {
                    componentDepth = depth;
                    intentFilterDepth = -1;
                }

                else if (tagName.equals("intent-filter")
                        && componentDepth == depth - 1) {

                    intentFilterDepth = depth;
                }

                else if (intentFilterDepth == depth - 1
                        && (tagName.equals("action")
                        || tagName.equals("category"))) {

                    String name = parser.getAttributeValue(
                            ANDROID_NS, "name"
                    );

                    if (name != null && !name.isEmpty()) {
                        intents.add(name);
                    }
                }

                // ---------------------------------
                // 3. Hardware features
                // ---------------------------------

                if (tagName.equals("uses-feature")) {

                    String name = parser.getAttributeValue(
                            ANDROID_NS, "name"
                    );

                    if (name != null && !name.isEmpty()) {
                        hardwareFeatures.add(name);
                    }
                }
            }

            else if (eventType == XmlPullParser.END_TAG) {

                int depth = parser.getDepth();

                if (depth == intentFilterDepth) {
                    intentFilterDepth = -1;
                }

                if (depth == componentDepth) {
                    componentDepth = -1;
                    intentFilterDepth = -1;
                }
            }

            eventType = parser.next();
        }

        return new ManifestFeatures(
                permissions,
                intents,
                hardwareFeatures
        );
    }

    /**
     * Kết quả trích xuất Manifest.
     */
    public static class ManifestFeatures {

        private final Set<String> permissions;
        private final Set<String> intents;
        private final Set<String> hardwareFeatures;

        public ManifestFeatures(
                Set<String> permissions,
                Set<String> intents,
                Set<String> hardwareFeatures) {

            this.permissions = permissions;
            this.intents = intents;
            this.hardwareFeatures = hardwareFeatures;
        }

        public Set<String> getPermissions() {
            return permissions;
        }

        public Set<String> getIntents() {
            return intents;
        }

        public Set<String> getHardwareFeatures() {
            return hardwareFeatures;
        }

        /**
         * Chuyển các feature thành đúng định dạng
         * mà FeatureVectorizer đang sử dụng.
         */
        public Set<String> toFeatureSet() {

            Set<String> features = new HashSet<>();

            for (String permission : permissions) {
                features.add("permission:" + permission);
            }

            for (String intent : intents) {
                features.add("intent:" + intent);
            }

            for (String feature : hardwareFeatures) {
                features.add("hardware:" + feature);
            }

            return features;
        }
    }
}
