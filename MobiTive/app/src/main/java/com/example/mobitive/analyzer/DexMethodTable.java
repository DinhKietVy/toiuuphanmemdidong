package com.example.mobitive.analyzer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

/**
 * Minimal, allocation-light reader of the DEX method reference table
 * (method_ids), as proposed by MobiTive (Feng et al., 2020, Sec. III-B.3):
 * API calls are read from the binary symbol table instead of decompiling
 * or walking every bytecode instruction.
 *
 * Pure Java (no Android / dexlib2 dependency) so it can be unit-tested on the
 * JVM and mirrored 1:1 by the Python extractor (src/mobitive/dex_extractor.py).
 *
 * Descriptor format (identical to the training dictionary):
 *   Landroid/view/View;->setVisibility(I)V
 *   Landroid/view/ViewGroup;->drawChild(Landroid/graphics/Canvas; Landroid/view/View; J)Z
 *
 * Every offset/index read from the file is bounds-checked: the input is an
 * untrusted (possibly malicious) APK.
 */
public final class DexMethodTable {

    /** Receives each method reference whose defining class passes the filter. */
    public interface Sink {
        void accept(String definingClass, String descriptor);
    }

    /** Cheap pre-filter on the defining class, checked before any other decoding. */
    public interface ClassFilter {
        boolean test(String classDescriptor);
    }

    private static final int HEADER_SIZE = 0x70;
    private static final int ENDIAN_CONSTANT = 0x12345678;

    private final byte[] data;
    private final int stringIdsSize, stringIdsOff;
    private final int typeIdsSize, typeIdsOff;
    private final int protoIdsSize, protoIdsOff;
    private final int methodIdsSize, methodIdsOff;
    private final int classDefsSize, classDefsOff;

    // Lazily decoded strings: each type/proto is decoded at most once per DEX.
    private final String[] typeCache;
    private final String[] protoParamsCache;

    public DexMethodTable(byte[] data) throws IOException {
        if (data == null || data.length < HEADER_SIZE) {
            throw new IOException("DEX quá nhỏ hoặc rỗng.");
        }
        this.data = data;
        if (data[0] != 'd' || data[1] != 'e' || data[2] != 'x' || data[3] != '\n') {
            throw new IOException("Sai DEX magic.");
        }
        if (u4(0x28) != ENDIAN_CONSTANT) {
            throw new IOException("DEX endian không được hỗ trợ.");
        }
        stringIdsSize = count(0x38);
        stringIdsOff = u4(0x3C);
        typeIdsSize = count(0x40);
        typeIdsOff = u4(0x44);
        protoIdsSize = count(0x48);
        protoIdsOff = u4(0x4C);
        methodIdsSize = count(0x58);
        methodIdsOff = u4(0x5C);
        classDefsSize = count(0x60);
        classDefsOff = u4(0x64);

        checkSection(stringIdsOff, stringIdsSize, 4);
        checkSection(typeIdsOff, typeIdsSize, 4);
        checkSection(protoIdsOff, protoIdsSize, 12);
        checkSection(methodIdsOff, methodIdsSize, 8);
        checkSection(classDefsOff, classDefsSize, 32);

        typeCache = new String[typeIdsSize];
        protoParamsCache = new String[protoIdsSize];
    }

    public int methodRefCount() {
        return methodIdsSize;
    }

    public int classDefCount() {
        return classDefsSize;
    }

    /** Adds the descriptor of every class DEFINED in this DEX (class_defs). */
    public void collectDefinedClasses(Collection<String> out) throws IOException {
        for (int i = 0; i < classDefsSize; i++) {
            out.add(type(u4(classDefsOff + i * 32)));
        }
    }

    /**
     * Streams method_ids. Name/prototype are decoded only for references
     * whose defining class passes {@code filter}.
     *
     * @return number of references passed to the sink
     */
    public int forEachMethodRef(ClassFilter filter, Sink sink) throws IOException {
        int accepted = 0;
        StringBuilder sb = new StringBuilder(128);
        for (int i = 0; i < methodIdsSize; i++) {
            int item = methodIdsOff + i * 8;
            String definingClass = type(u2(item));
            if (!filter.test(definingClass)) {
                continue;
            }
            int protoIdx = u2(item + 2);
            String name = string(u4(item + 4));

            sb.setLength(0);
            sb.append(definingClass).append("->").append(name);
            appendProto(sb, protoIdx);
            sink.accept(definingClass, sb.toString());
            accepted++;
        }
        return accepted;
    }

    // ------------------------------------------------------------------

    private void appendProto(StringBuilder sb, int protoIdx) throws IOException {
        if (protoIdx >= protoIdsSize) {
            throw new IOException("proto_idx ngoài phạm vi.");
        }
        String params = protoParamsCache[protoIdx];
        int item = protoIdsOff + protoIdx * 12;
        if (params == null) {
            int paramsOff = u4(item + 8);
            StringBuilder p = new StringBuilder(64).append('(');
            if (paramsOff != 0) {
                int size = count(paramsOff);
                checkSection(paramsOff + 4, size, 2);
                for (int k = 0; k < size; k++) {
                    if (k > 0) p.append(' ');
                    p.append(type(u2(paramsOff + 4 + k * 2)));
                }
            }
            p.append(')');
            params = p.toString();
            protoParamsCache[protoIdx] = params;
        }
        sb.append(params).append(type(u4(item + 4)));
    }

    private String type(int typeIdx) throws IOException {
        if (typeIdx < 0 || typeIdx >= typeIdsSize) {
            throw new IOException("type_idx ngoài phạm vi.");
        }
        String cached = typeCache[typeIdx];
        if (cached == null) {
            cached = string(u4(typeIdsOff + typeIdx * 4));
            typeCache[typeIdx] = cached;
        }
        return cached;
    }

    private String string(int stringIdx) throws IOException {
        if (stringIdx < 0 || stringIdx >= stringIdsSize) {
            throw new IOException("string_idx ngoài phạm vi.");
        }
        int off = u4(stringIdsOff + stringIdx * 4);
        if (off < 0 || off >= data.length) {
            throw new IOException("string_data_off ngoài phạm vi.");
        }
        // Skip ULEB128 utf16_size (max 5 bytes).
        int p = off;
        for (int k = 0; ; k++) {
            if (p >= data.length || k >= 5) throw new IOException("ULEB128 hỏng.");
            if ((data[p++] & 0x80) == 0) break;
        }
        int start = p;
        boolean ascii = true;
        while (p < data.length && data[p] != 0) {
            if (data[p] < 0) ascii = false;
            p++;
        }
        if (p >= data.length) throw new IOException("Chuỗi DEX không kết thúc.");
        return ascii
                ? new String(data, start, p - start, StandardCharsets.ISO_8859_1)
                : decodeMutf8(start, p);
    }

    /** Modified UTF-8 → UTF-16 (surrogates are encoded as separate 3-byte units). */
    private String decodeMutf8(int start, int end) throws IOException {
        char[] out = new char[end - start];
        int n = 0;
        int p = start;
        while (p < end) {
            int a = data[p++] & 0xFF;
            if (a < 0x80) {
                out[n++] = (char) a;
            } else if ((a & 0xE0) == 0xC0) {
                if (p >= end) throw new IOException("MUTF-8 hỏng.");
                int b = data[p++] & 0x3F;
                out[n++] = (char) (((a & 0x1F) << 6) | b);
            } else if ((a & 0xF0) == 0xE0) {
                if (p + 1 >= end) throw new IOException("MUTF-8 hỏng.");
                int b = data[p++] & 0x3F;
                int c = data[p++] & 0x3F;
                out[n++] = (char) (((a & 0x0F) << 12) | (b << 6) | c);
            } else {
                throw new IOException("MUTF-8 hỏng.");
            }
        }
        return new String(out, 0, n);
    }

    private int u2(int off) throws IOException {
        if (off < 0 || off + 2 > data.length) throw new IOException("Đọc ngoài DEX.");
        return (data[off] & 0xFF) | ((data[off + 1] & 0xFF) << 8);
    }

    private int u4(int off) throws IOException {
        if (off < 0 || off + 4 > data.length) throw new IOException("Đọc ngoài DEX.");
        return (data[off] & 0xFF)
                | ((data[off + 1] & 0xFF) << 8)
                | ((data[off + 2] & 0xFF) << 16)
                | ((data[off + 3] & 0xFF) << 24);
    }

    /** u4 used as a size: must be non-negative and plausible. */
    private int count(int off) throws IOException {
        int value = u4(off);
        if (value < 0 || value > data.length) throw new IOException("Kích thước section không hợp lệ.");
        return value;
    }

    private void checkSection(int off, int size, int itemBytes) throws IOException {
        if (size == 0) return;
        long end = (long) off + (long) size * itemBytes;
        if (off < 0 || end > data.length) {
            throw new IOException("Section nằm ngoài DEX.");
        }
    }
}
