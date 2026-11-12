package com.example.mobitive.m4;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import com.example.mobitive.ml.MalwareClassifier;
import org.tensorflow.lite.DataType;
import org.tensorflow.lite.Interpreter;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Arrays;

/** Non-baseline inference only. M2.1 model assets are never changed by M4. */
public final class M4VariantClassifier implements AutoCloseable {
    private final Interpreter interpreter;
    private final boolean mlpInput;

    public M4VariantClassifier(Context context, M4ModelCatalog.Choice choice) throws IOException {
        if (choice == null || choice.isBaseline()) {
            throw new IllegalArgumentException("Use baseline MalwareClassifier for GRU-128 FP32.");
        }
        // Allow only model names from the fixed catalog, and verify installed asset.
        boolean allowed = false;
        for (M4ModelCatalog.Choice item : M4ModelCatalog.installed(context)) {
            if (item.id.equals(choice.id) && item.fileName.equals(choice.fileName)) {
                allowed = true;
                break;
            }
        }
        if (!allowed) throw new IOException("Model chưa được cài đặt: " + choice.id);

        MappedByteBuffer buffer;
        try (AssetFileDescriptor fd = context.getAssets().openFd("models/" + choice.fileName);
             FileInputStream stream = new FileInputStream(fd.getFileDescriptor())) {
            buffer = stream.getChannel().map(FileChannel.MapMode.READ_ONLY,
                    fd.getStartOffset(), fd.getDeclaredLength());
        }
        Interpreter.Options options = new Interpreter.Options();
        options.setNumThreads(choice.threads);
        Interpreter candidate = new Interpreter(buffer, options);
        boolean isMlp;
        try {
            int[] shape = candidate.getInputTensor(0).shape();
            isMlp = Arrays.equals(shape, new int[]{1, 2915});
            if (!isMlp && !Arrays.equals(shape, new int[]{1, 1, 2915})) {
                throw new IllegalStateException("Unsupported model input shape: " + Arrays.toString(shape));
            }
            if (!Arrays.equals(candidate.getOutputTensor(0).shape(), new int[]{1, 2}) ||
                    candidate.getInputTensor(0).dataType() != DataType.FLOAT32 ||
                    candidate.getOutputTensor(0).dataType() != DataType.FLOAT32) {
                throw new IllegalStateException("Model expects float32 input and [1,2] float32 output.");
            }
        } catch (RuntimeException e) {
            candidate.close();
            throw e;
        }
        interpreter = candidate;
        mlpInput = isMlp;
    }

    public MalwareClassifier.Prediction predict(float[] vector) {
        if (vector == null || vector.length != 2915) {
            throw new IllegalArgumentException("Expected 2915 features.");
        }
        for (float value : vector) {
            if (!Float.isFinite(value)) throw new IllegalArgumentException("Invalid feature value.");
        }
        Object input;
        if (mlpInput) {
            float[][] flat = new float[1][2915];
            System.arraycopy(vector, 0, flat[0], 0, vector.length);
            input = flat;
        } else {
            float[][][] sequence = new float[1][1][2915];
            System.arraycopy(vector, 0, sequence[0][0], 0, vector.length);
            input = sequence;
        }
        float[][] output = new float[1][2];
        interpreter.run(input, output);
        return new MalwareClassifier.Prediction(
                output[0][1] > output[0][0], output[0][0], output[0][1]);
    }

    @Override public void close() { interpreter.close(); }
}
