package com.github.elkanuco.stream.encryption;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

public class StreamUtils {

    PipedOutputStream pipedOutputStream(PipedInputStream encryptionPipeInputStream) {
        PipedOutputStream encryptionPipedOutputStream;
        try {
            @SuppressWarnings("java:S2095") final PipedOutputStream localEncryptionPipedOutputStream = new PipedOutputStream(encryptionPipeInputStream);
            encryptionPipedOutputStream = localEncryptionPipedOutputStream;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return encryptionPipedOutputStream;
    }
}
