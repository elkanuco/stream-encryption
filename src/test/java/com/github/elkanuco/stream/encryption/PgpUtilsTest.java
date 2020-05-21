package com.github.elkanuco.stream.encryption;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

class PgpUtilsTest {

    @Test
    void cannotReadPublicKey() throws IOException {
        //given
        PgpUtils instance = new PgpUtils();
        final File invalidFile = File.createTempFile("INVALID", ".asc");
        invalidFile.deleteOnExit();
        final IllegalStateException result;
        try (InputStream publicKeyFileStream = new FileInputStream(invalidFile)) {
            //when
            result = Assertions.assertThrows(IllegalStateException.class, () -> instance.readPublicKey(publicKeyFileStream));
        }
        //then
        Assertions.assertEquals("Unable to read public key for PGP encryption.", result.getMessage());
    }


}