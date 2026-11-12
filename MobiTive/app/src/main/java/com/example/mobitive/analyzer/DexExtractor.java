package com.example.mobitive.analyzer;

import android.os.Debug;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * M5: API-call extraction from the DEX method reference table (method_ids),
 * following the MobiTive paper ("binary code" extraction, no decompiling).
 *
 * Previous versions (M0–M3.4) walked every bytecode instruction with dexlib2
 * and kept the targets of invoke-* instructions. That was ~90% of scan time.
 * Every framework method that is invoked has an entry in method_ids, so reading
 * the table yields the same platform-API set at O(#method_ids) cost.
 *
 * Feature definition (shared with the Python extractor):
 *   method_ids entries whose defining class starts with a FRAMEWORK_PREFIX
 *   and does NOT start with a BUNDLED_LIBRARY_PREFIX.
 *
 * Note: we deliberately do NOT drop classes defined inside the APK: R8 inserts
 * stub class_defs for framework classes newer than minSdk (AppComponentFactory,
 * Toast$Callback, ...), and those are real platform API uses.
 */
public class DexExtractor {

    private static final String TAG = "MobiTiveDexProfile";

    /** Defensive caps against zip bombs / malformed APKs. */
    private static final long MAX_DEX_BYTES = 128L * 1024 * 1024;
    private static final long MAX_TOTAL_DEX_BYTES = 512L * 1024 * 1024;

    private static final Pattern DEX_ENTRY = Pattern.compile("classes(\\d+)?\\.dex");

    static final String[] FRAMEWORK_PREFIXES = {
            "Landroid/",
            "Ljava/",
            "Ljavax/",
            "Ldalvik/",
            "Lorg/json/",
            "Lorg/xml/",
            "Lorg/w3c/",
            "Lorg/xmlpull/"
    };

    /** Old support/arch libraries live under Landroid/ but are bundled app code. */
    static final String[] BUNDLED_LIBRARY_PREFIXES = {
            "Landroid/support/",
            "Landroid/arch/"
    };

    public DexFeatures extract(File apkFile) throws IOException {

        if (apkFile == null || !apkFile.exists()) {
            throw new IOException("APK file không tồn tại.");
        }

        // descriptor -> number of DEX files that reference it.
        Map<String, Integer> apiCallCount = new HashMap<>(8192);
        int[] bundledRefCount = {0};

        int dexFileCount = 0;
        int classDefCount = 0;
        int methodRefCount = 0;
        int frameworkMethodRefCount = 0;
        long totalDexBytes = 0;

        try (ZipFile zipFile = new ZipFile(apkFile)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();

            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                if (!DEX_ENTRY.matcher(entryName).matches()) {
                    continue;
                }
                dexFileCount++;

                final long wall0 = System.nanoTime();
                final long cpu0 = Debug.threadCpuTimeNanos();

                byte[] bytes = readEntry(zipFile, entry);
                totalDexBytes += bytes.length;
                if (totalDexBytes > MAX_TOTAL_DEX_BYTES) {
                    throw new IOException("Tổng dung lượng DEX vượt giới hạn.");
                }

                final long wall1 = System.nanoTime();
                final long cpu1 = Debug.threadCpuTimeNanos();

                DexMethodTable table = new DexMethodTable(bytes);
                classDefCount += table.classDefCount();
                methodRefCount += table.methodRefCount();

                int accepted = table.forEachMethodRef(
                        DexExtractor::isFrameworkClass,
                        (definingClass, descriptor) -> {
                            // Static initializers are definitions (e.g. R8 API stubs), never calls.
                            if (descriptor.contains(";-><clinit>(")) {
                                return;
                            }
                            if (isBundledLibraryClass(definingClass)) {
                                bundledRefCount[0]++;
                                return;
                            }
                            Integer c = apiCallCount.get(descriptor);
                            apiCallCount.put(descriptor, c == null ? 1 : c + 1);
                        });
                frameworkMethodRefCount += accepted;

                final long wall2 = System.nanoTime();
                final long cpu2 = Debug.threadCpuTimeNanos();
                Log.i(TAG, String.format(Locale.US,
                        "mode=method_ids dex=%s bytes=%d unzip_wall_ms=%.3f unzip_cpu_ms=%.3f " +
                        "parse_wall_ms=%.3f parse_cpu_ms=%.3f classes=%d method_refs=%d framework_refs=%d",
                        entryName, bytes.length,
                        (wall1 - wall0) / 1e6, (cpu1 - cpu0) / 1e6,
                        (wall2 - wall1) / 1e6, (cpu2 - cpu1) / 1e6,
                        table.classDefCount(), table.methodRefCount(), accepted));
            }
        }

        if (dexFileCount == 0) {
            throw new IOException("Không tìm thấy classes.dex trong APK.");
        }

        return new DexFeatures(
                apiCallCount.keySet(),
                apiCallCount,
                dexFileCount,
                classDefCount,
                methodRefCount,
                frameworkMethodRefCount,
                bundledRefCount[0]
        );
    }

    private static byte[] readEntry(ZipFile zipFile, ZipEntry entry) throws IOException {
        long declared = entry.getSize();
        if (declared > MAX_DEX_BYTES) {
            throw new IOException("DEX quá lớn: " + entry.getName());
        }
        try (InputStream input = zipFile.getInputStream(entry)) {
            if (declared >= 0) {
                byte[] out = new byte[(int) declared];
                int off = 0;
                while (off < out.length) {
                    int n = input.read(out, off, out.length - off);
                    if (n < 0) throw new IOException("DEX bị cắt cụt: " + entry.getName());
                    off += n;
                }
                return out;
            }
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(1 << 20);
            byte[] chunk = new byte[64 * 1024];
            int n;
            while ((n = input.read(chunk)) != -1) {
                buffer.write(chunk, 0, n);
                if (buffer.size() > MAX_DEX_BYTES) {
                    throw new IOException("DEX quá lớn: " + entry.getName());
                }
            }
            return buffer.toByteArray();
        }
    }

    static boolean isBundledLibraryClass(String definingClass) {
        for (String prefix : BUNDLED_LIBRARY_PREFIXES) {
            if (definingClass.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    static boolean isFrameworkClass(String definingClass) {
        for (String prefix : FRAMEWORK_PREFIXES) {
            if (definingClass.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Kết quả phân tích DEX.
     */
    public static class DexFeatures {

        private final Set<String> apiCalls;
        /** API descriptor -> number of DEX files referencing it (>= 1). */
        private final Map<String, Integer> apiCallCount;

        private final int dexFileCount;
        private final int classDefCount;
        private final int methodRefCount;
        private final int frameworkMethodRefCount;
        private final int bundledLibraryRefCount;

        public DexFeatures(
                Set<String> apiCalls,
                Map<String, Integer> apiCallCount,
                int dexFileCount,
                int classDefCount,
                int methodRefCount,
                int frameworkMethodRefCount,
                int bundledLibraryRefCount) {

            this.apiCalls = Collections.unmodifiableSet(new HashSet<>(apiCalls));
            this.apiCallCount = Collections.unmodifiableMap(new HashMap<>(apiCallCount));
            this.dexFileCount = dexFileCount;
            this.classDefCount = classDefCount;
            this.methodRefCount = methodRefCount;
            this.frameworkMethodRefCount = frameworkMethodRefCount;
            this.bundledLibraryRefCount = bundledLibraryRefCount;
        }

        public Set<String> getApiCalls() { return apiCalls; }
        public Map<String, Integer> getApiCallCount() { return apiCallCount; }
        public int getUniqueApiCallCount() { return apiCalls.size(); }
        public int getDexFileCount() { return dexFileCount; }
        public int getClassDefCount() { return classDefCount; }
        public int getMethodRefCount() { return methodRefCount; }
        public int getFrameworkMethodRefCount() { return frameworkMethodRefCount; }
        public int getBundledLibraryRefCount() { return bundledLibraryRefCount; }
    }
}
