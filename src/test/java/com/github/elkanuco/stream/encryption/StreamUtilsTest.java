package com.github.elkanuco.stream.encryption;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import static org.junit.jupiter.api.Assertions.assertThrows;

class StreamUtilsTest {

    @Test
    void pipedOutputStream() throws IOException {
        // Given
        @SuppressWarnings("java:S2095") final PipedInputStream pipedInputStream = new PipedInputStream();
        pipedInputStream.connect(new PipedOutputStream());
        // When & Then
        final StreamUtils instance = new StreamUtils();
        assertThrows(IllegalStateException.class, () -> instance.pipedOutputStream(pipedInputStream));
    }
}