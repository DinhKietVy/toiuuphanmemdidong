package com.example.mobitive;

import com.example.mobitive.utils.FileUtils;
import com.example.mobitive.utils.HashUtils;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class FileUtilsTest {

    @Test
    public void copiesAndHashesInOnePassAcrossManyBuffers() throws IOException {
        byte[] data = new byte[1_000_003]; // > 3 buffers, not a multiple of the buffer size
        new Random(42).nextBytes(data);
        File out = File.createTempFile("mobitive_test_", ".apk");
        try {
            FileUtils.CopyResult result =
                    FileUtils.copyWithSha256(new ByteArrayInputStream(data), out);

            assertEquals(data.length, result.bytes);
            assertArrayEquals(data, Files.readAllBytes(out.toPath()));
            assertEquals(HashUtils.toHex(HashUtils.newSha256().digest(data)), result.sha256);
        } finally {
            out.delete();
        }
    }

    @Test
    public void knownVector() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                HashUtils.toHex(HashUtils.newSha256().digest("abc".getBytes())));
    }

    @Test
    public void rejectsEmptyAndNullInput() throws IOException {
        File out = File.createTempFile("mobitive_test_", ".apk");
        try {
            for (ByteArrayInputStream in : Arrays.asList(new ByteArrayInputStream(new byte[0]), null)) {
                try {
                    FileUtils.copyWithSha256(in, out);
                    fail("Expected IOException");
                } catch (IOException expected) {
                    // ok
                }
            }
        } finally {
            out.delete();
        }
    }
}
