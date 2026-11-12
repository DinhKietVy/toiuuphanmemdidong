package com.example.mobitive.ml;

import android.content.Context;
import android.content.res.AssetFileDescriptor;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

/**
 * The single place that loads a .tflite model from assets.
 * Memory-maps the asset (no copy into the Java heap); requires the asset to be
 * stored uncompressed, which AGP does by default for ".tflite".
 */
public final class ModelAssets {

    private ModelAssets() { }

    public static final class Model {
        public final MappedByteBuffer buffer;
        public final long bytes;

        Model(MappedByteBuffer buffer, long bytes) {
            this.buffer = buffer;
            this.bytes = bytes;
        }
    }

    /** @param assetPath e.g. "models/mobitive_gru.tflite" */
    public static Model map(Context context, String assetPath) throws IOException {
        try (AssetFileDescriptor fd = context.getAssets().openFd(assetPath);
             FileInputStream stream = new FileInputStream(fd.getFileDescriptor())) {
            MappedByteBuffer buffer = stream.getChannel().map(FileChannel.MapMode.READ_ONLY,
                    fd.getStartOffset(), fd.getDeclaredLength());
            return new Model(buffer, fd.getDeclaredLength());
        }
    }
}
