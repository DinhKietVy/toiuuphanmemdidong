package com.example.mobitive.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;

public final class FileUtils {

    /**
     * 256 KB: large enough to amortize ContentResolver/binder and syscall cost,
     * small enough to stay out of the large-object heap churn.
     */
    static final int COPY_BUFFER_BYTES = 256 * 1024;

    private FileUtils() { }

    /** Result of {@link #copyWithSha256}. */
    public static final class CopyResult {
        public final long bytes;
        public final String sha256;

        CopyResult(long bytes, String sha256) {
            this.bytes = bytes;
            this.sha256 = sha256;
        }
    }

    /**
     * M6: copies {@code input} to {@code output} and computes SHA-256 of the
     * same bytes in ONE pass, so the APK is no longer read a second time just
     * to build the cache key. The hash covers exactly the bytes written.
     */
    public static CopyResult copyWithSha256(InputStream input, File output) throws IOException {
        if (input == null) {
            throw new IOException("Không thể mở APK.");
        }
        MessageDigest digest = HashUtils.newSha256();
        byte[] buffer = new byte[COPY_BUFFER_BYTES];
        long total = 0;
        try (OutputStream out = new FileOutputStream(output)) {
            int n;
            while ((n = input.read(buffer)) != -1) {
                digest.update(buffer, 0, n);
                out.write(buffer, 0, n);
                total += n;
            }
        }
        if (total <= 0) {
            throw new IOException("APK rỗng.");
        }
        return new CopyResult(total, HashUtils.toHex(digest.digest()));
    }
}
