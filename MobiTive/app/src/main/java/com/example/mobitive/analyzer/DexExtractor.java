
package com.example.mobitive.analyzer;

import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class DexExtractor {

    private static final String[] FRAMEWORK_PREFIXES = {
            "Landroid/",
            "Ljava/",
            "Ljavax/",
            "Ldalvik/",
            "Lorg/json/",
            "Lorg/xml/",
            "Lorg/w3c/",
            "Lorg/xmlpull/"
    };

    /**
     * Trích xuất API calls từ tất cả DEX trong APK.
     */
    public DexFeatures extract(File apkFile, File cacheDir)
            throws IOException {

        if (apkFile == null || !apkFile.exists()) {
            throw new IOException("APK file không tồn tại.");
        }

        if (cacheDir == null) {
            throw new IOException("Cache directory không hợp lệ.");
        }

        if (!cacheDir.exists() && !cacheDir.mkdirs()) {
            throw new IOException("Không thể tạo cache directory.");
        }

        Set<String> apiCalls = new TreeSet<>();
        Map<String, Integer> apiCallCount = new HashMap<>();

        int invokeInstructionCount = 0;
        int matchedMethodCount = 0;
        int frameworkInvokeCount = 0;

        int parsedClassCount = 0;
        int parsedMethodCount = 0;

        List<File> temporaryDexFiles = new ArrayList<>();

        try (ZipFile zipFile = new ZipFile(apkFile)) {

            Enumeration<? extends ZipEntry> entries =
                    zipFile.entries();

            int dexIndex = 0;

            while (entries.hasMoreElements()) {

                ZipEntry entry = entries.nextElement();

                String entryName = entry.getName();

                // Chỉ xử lý classes.dex, classes2.dex,...
                if (!isDexEntry(entryName)) {
                    continue;
                }

                dexIndex++;

                File dexFile = new File(
                        cacheDir,
                        "mobitive_temp_" + System.nanoTime() + ".dex"
                );

                temporaryDexFiles.add(dexFile);

                // Giải nén DEX vào file tạm.
                try (
                        InputStream input =
                                zipFile.getInputStream(entry);

                        FileOutputStream output =
                                new FileOutputStream(dexFile)
                ) {
                    byte[] buffer = new byte[8192];
                    int length;

                    while ((length = input.read(buffer)) != -1) {
                        output.write(buffer, 0, length);
                    }
                }

                // Đọc DEX bằng dexlib2.
                DexFile dex = DexFileFactory.loadDexFile(
                        dexFile,
                        Opcodes.getDefault()
                );

                for (ClassDef classDef : dex.getClasses()) {

                    parsedClassCount++;

                    for (Method method : classDef.getMethods()) {

                        parsedMethodCount++;

                        MethodImplementation implementation =
                                method.getImplementation();

                        if (implementation == null) {
                            continue;
                        }

                        for (Instruction instruction :
                                implementation.getInstructions()) {

                            String opcodeName = instruction
                                    .getOpcode()
                                    .name()
                                    .toLowerCase(Locale.ROOT)
                                    .replace('_', '-');

                            // Tương đương instruction_name.startswith("invoke-")
                            if (!opcodeName.startsWith("invoke-")) {
                                continue;
                            }

                            invokeInstructionCount++;

                            if (!(instruction instanceof ReferenceInstruction)) {
                                continue;
                            }

                            Object reference =
                                    ((ReferenceInstruction) instruction)
                                            .getReference();

                            if (!(reference instanceof MethodReference)) {
                                continue;
                            }

                            MethodReference methodReference =
                                    (MethodReference) reference;

                            String descriptor =
                                    buildMethodDescriptor(methodReference);

                            matchedMethodCount++;

                            if (!isFrameworkApi(descriptor)) {
                                continue;
                            }

                            frameworkInvokeCount++;

                            apiCalls.add(descriptor);

                            Integer count = apiCallCount.get(descriptor);

                            apiCallCount.put(
                                    descriptor,
                                    count == null ? 1 : count + 1
                            );
                        }
                    }
                }
            }

            if (dexIndex == 0) {
                throw new IOException(
                        "Không tìm thấy classes.dex trong APK."
                );
            }

        } finally {

            // Xóa các file DEX tạm sau khi phân tích.
            for (File file : temporaryDexFiles) {
                if (file.exists()) {
                    // Nếu không xóa được ngay, Android có thể dọn sau.
                    file.delete();
                }
            }
        }

        return new DexFeatures(
                apiCalls,
                apiCallCount,
                invokeInstructionCount,
                matchedMethodCount,
                frameworkInvokeCount,
                parsedClassCount,
                parsedMethodCount
        );
    }

    /**
     * Kiểm tra tên entry có phải DEX hay không.
     */
    private boolean isDexEntry(String name) {

        if (name == null || !name.matches("classes(\\d+)?\\.dex")) {
            return false;
        }

        return true;
    }

    /**
     * Tạo descriptor theo định dạng Androguard output
     * được sử dụng trong Python extractor.
     *
     * Ví dụ:
     * Landroid/view/View;->setVisibility(I)V
     *
     * Với nhiều tham số, Androguard dùng dấu cách:
     * Landroid/view/ViewGroup;->drawChild(
     * Landroid/graphics/Canvas; Landroid/view/View; J)Z
     */
    private String buildMethodDescriptor(
            MethodReference methodReference) {

        StringBuilder descriptor = new StringBuilder();

        descriptor.append(methodReference.getDefiningClass());
        descriptor.append("->");
        descriptor.append(methodReference.getName());
        descriptor.append("(");

        boolean first = true;

        for (CharSequence parameter :
                methodReference.getParameterTypes()) {

            if (!first) {
                descriptor.append(" ");
            }

            descriptor.append(parameter);
            first = false;
        }

        descriptor.append(")");
        descriptor.append(methodReference.getReturnType());

        return descriptor.toString();
    }

    /**
     * Kiểm tra API có thuộc framework prefixes hay không.
     */
    private boolean isFrameworkApi(String descriptor) {

        for (String prefix : FRAMEWORK_PREFIXES) {

            if (descriptor.startsWith(prefix)) {
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
        private final Map<String, Integer> apiCallCount;

        private final int invokeInstructionCount;
        private final int matchedMethodCount;
        private final int frameworkInvokeCount;

        private final int parsedClassCount;
        private final int parsedMethodCount;

        public DexFeatures(
                Set<String> apiCalls,
                Map<String, Integer> apiCallCount,
                int invokeInstructionCount,
                int matchedMethodCount,
                int frameworkInvokeCount,
                int parsedClassCount,
                int parsedMethodCount) {

            this.apiCalls = Collections.unmodifiableSet(
                    new HashSet<>(apiCalls)
            );

            this.apiCallCount = Collections.unmodifiableMap(
                    new HashMap<>(apiCallCount)
            );

            this.invokeInstructionCount = invokeInstructionCount;
            this.matchedMethodCount = matchedMethodCount;
            this.frameworkInvokeCount = frameworkInvokeCount;

            this.parsedClassCount = parsedClassCount;
            this.parsedMethodCount = parsedMethodCount;
        }

        public Set<String> getApiCalls() {
            return apiCalls;
        }

        public Map<String, Integer> getApiCallCount() {
            return apiCallCount;
        }

        public int getUniqueApiCallCount() {
            return apiCalls.size();
        }

        public int getInvokeInstructionCount() {
            return invokeInstructionCount;
        }

        public int getMatchedMethodCount() {
            return matchedMethodCount;
        }

        public int getFrameworkInvokeCount() {
            return frameworkInvokeCount;
        }

        public int getParsedClassCount() {
            return parsedClassCount;
        }

        public int getParsedMethodCount() {
            return parsedMethodCount;
        }
    }
}
