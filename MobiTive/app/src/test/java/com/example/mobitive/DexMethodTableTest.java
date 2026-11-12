package com.example.mobitive;

import com.example.mobitive.analyzer.DexMethodTable;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/** JVM tests for the method_ids parser using a hand-built minimal DEX. */
public class DexMethodTableTest {

    private static final String[] STRINGS = {
            "Landroid/view/View;",          // 0
            "Lcom/app/Main;",               // 1
            "V",                            // 2
            "I",                            // 3
            "setVisibility",                // 4
            "onCreate",                     // 5
            "Ljava/lang/String;",           // 6
            "Landroid/support/v4/Foo;",     // 7
            "bar",                          // 8
            "café",                    // 9 non-ASCII (MUTF-8 2-byte)
    };
    // type_idx -> string_idx
    private static final int[] TYPES = {0, 1, 2, 3, 6, 7};
    // {return type, param types...}
    private static final int[][] PROTOS = {
            {2, 3},       // (I)V
            {2},          // ()V
            {3, 4, 3},    // (Ljava/lang/String; I)I
    };
    // {class type, proto, name string}
    private static final int[][] METHODS = {
            {0, 0, 4},    // View.setVisibility(I)V
            {1, 1, 5},    // Main.onCreate()V
            {5, 1, 8},    // support Foo.bar()V
            {4, 2, 9},    // String.café(String, I)I
    };
    private static final int[] CLASS_DEFS = {1, 5};

    static byte[] buildDex() {
        int stringIdsOff = 0x70;
        int typeIdsOff = stringIdsOff + STRINGS.length * 4;
        int protoIdsOff = typeIdsOff + TYPES.length * 4;
        int methodIdsOff = protoIdsOff + PROTOS.length * 12;
        int classDefsOff = methodIdsOff + METHODS.length * 8;
        int dataOff = classDefsOff + CLASS_DEFS.length * 32;

        ByteArrayOutputStream dataSection = new ByteArrayOutputStream();
        int[] stringDataOff = new int[STRINGS.length];
        for (int i = 0; i < STRINGS.length; i++) {
            stringDataOff[i] = dataOff + dataSection.size();
            dataSection.write(STRINGS[i].length()); // uleb128 utf16 size (< 128)
            byte[] b = STRINGS[i].getBytes(StandardCharsets.UTF_8);
            dataSection.write(b, 0, b.length);
            dataSection.write(0);
        }
        while (dataSection.size() % 4 != 0) dataSection.write(0);
        int[] paramsOff = new int[PROTOS.length];
        for (int i = 0; i < PROTOS.length; i++) {
            int n = PROTOS[i].length - 1;
            if (n == 0) continue;
            paramsOff[i] = dataOff + dataSection.size();
            ByteBuffer tl = le(4 + n * 2 + (n % 2) * 2);
            tl.putInt(n);
            for (int k = 1; k <= n; k++) tl.putShort((short) PROTOS[i][k]);
            dataSection.write(tl.array(), 0, tl.capacity());
        }

        ByteBuffer dex = le(dataOff + dataSection.size());
        dex.put("dex\n035\0".getBytes(StandardCharsets.ISO_8859_1));
        dex.putInt(0x20, dex.capacity());
        dex.putInt(0x24, 0x70);
        dex.putInt(0x28, 0x12345678);
        dex.putInt(0x38, STRINGS.length).putInt(0x3C, stringIdsOff);
        dex.putInt(0x40, TYPES.length).putInt(0x44, typeIdsOff);
        dex.putInt(0x48, PROTOS.length).putInt(0x4C, protoIdsOff);
        dex.putInt(0x58, METHODS.length).putInt(0x5C, methodIdsOff);
        dex.putInt(0x60, CLASS_DEFS.length).putInt(0x64, classDefsOff);
        for (int i = 0; i < STRINGS.length; i++) dex.putInt(stringIdsOff + i * 4, stringDataOff[i]);
        for (int i = 0; i < TYPES.length; i++) dex.putInt(typeIdsOff + i * 4, TYPES[i]);
        for (int i = 0; i < PROTOS.length; i++) {
            int item = protoIdsOff + i * 12;
            dex.putInt(item, 2).putInt(item + 4, PROTOS[i][0]).putInt(item + 8, paramsOff[i]);
        }
        for (int i = 0; i < METHODS.length; i++) {
            int item = methodIdsOff + i * 8;
            dex.putShort(item, (short) METHODS[i][0]);
            dex.putShort(item + 2, (short) METHODS[i][1]);
            dex.putInt(item + 4, METHODS[i][2]);
        }
        for (int i = 0; i < CLASS_DEFS.length; i++) dex.putInt(classDefsOff + i * 32, CLASS_DEFS[i]);
        byte[] out = dex.array();
        byte[] data = dataSection.toByteArray();
        System.arraycopy(data, 0, out, dataOff, data.length);
        return out;
    }

    private static ByteBuffer le(int size) {
        return ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
    }

    @Test
    public void readsFrameworkMethodRefsInTrainingFormat() throws IOException {
        DexMethodTable table = new DexMethodTable(buildDex());
        Map<String, String> refs = new LinkedHashMap<>();
        int accepted = table.forEachMethodRef(
                c -> c.startsWith("Landroid/") || c.startsWith("Ljava/"),
                (cls, descriptor) -> refs.put(descriptor, cls));

        assertEquals(3, accepted);
        assertEquals(Arrays.asList(
                "Landroid/view/View;->setVisibility(I)V",
                "Landroid/support/v4/Foo;->bar()V",
                "Ljava/lang/String;->café(Ljava/lang/String; I)I"
        ), Arrays.asList(refs.keySet().toArray()));
        assertEquals(4, table.methodRefCount());
    }

    @Test
    public void collectsDefinedClasses() throws IOException {
        DexMethodTable table = new DexMethodTable(buildDex());
        Set<String> defined = new HashSet<>();
        table.collectDefinedClasses(defined);
        assertEquals(new HashSet<>(Arrays.asList(
                "Lcom/app/Main;", "Landroid/support/v4/Foo;")), defined);
    }

    @Test
    public void rejectsMalformedInput() {
        byte[] dex = buildDex();
        expectIOException(Arrays.copyOf(dex, 0x50));               // truncated header
        byte[] badMagic = dex.clone();
        badMagic[0] = 'x';
        expectIOException(badMagic);
        byte[] badOffset = dex.clone();
        ByteBuffer.wrap(badOffset).order(ByteOrder.LITTLE_ENDIAN).putInt(0x5C, 0x7FFFFFF0);
        expectIOException(badOffset);                               // method_ids out of file
    }

    private static void expectIOException(byte[] data) {
        try {
            DexMethodTable t = new DexMethodTable(data);
            t.forEachMethodRef(c -> true, (c, d) -> { });
            fail("Expected IOException");
        } catch (IOException expected) {
            // ok
        }
    }
}
