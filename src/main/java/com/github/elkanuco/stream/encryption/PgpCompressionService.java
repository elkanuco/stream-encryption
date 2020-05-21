package com.github.elkanuco.stream.encryption;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.output.CountingOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;


@Slf4j
class PgpCompressionService {

    final StreamUtils streamUtils;

    PgpCompressionService() {
        this.streamUtils = new StreamUtils();
    }

    InputStream compress(
            final InputStream inputStream,
            final ExecutorService executorService,
            final Configuration configuration
    ) {
        log.debug("Compressing the stream");
        @SuppressWarnings("java:S2095") final PipedInputStream compressionPipedInputStream = new PipedInputStream();
        final PipedOutputStream compressionPipedOutputStream = streamUtils.pipedOutputStream(compressionPipedInputStream);
        final CompletableFuture<Void> compression = CompletableFuture
                .runAsync(
                        () -> compress(inputStream, compressionPipedOutputStream, configuration),
                        executorService
                );
        compression.whenComplete((aVoid, throwable) -> log.debug("Finished compression"));

        return compressionPipedInputStream;
    }

    void compress(final InputStream inputStream,
                  final PipedOutputStream compressionPipedOutputStream,
                  final Configuration configuration) {
        final PGPCompressedDataGenerator pgpCompressedDataGenerator = new PGPCompressedDataGenerator(configuration.compressionAlgorithm.getCompressionAlgorithmTag());
        final PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();
        try (
                inputStream;
                Closeable closePgpCompressedDataGenerator = pgpCompressedDataGenerator::close;
                compressionPipedOutputStream;
                OutputStream compressedOutputStream = pgpCompressedDataGenerator.open(compressionPipedOutputStream);
                Closeable closePgpLiteralDataGenerator = pgpLiteralDataGenerator::close;
                final CountingOutputStream literalDataOutputStream = new CountingOutputStream(pgpLiteralDataGenerator.open(
                        compressedOutputStream,
                        PGPLiteralData.BINARY,
                        "PGP-encrypted-file",
                        Date.from(ZonedDateTime.now().toInstant()),
                        new byte[configuration.bufferSize])
                )
        ) {
            final long compressedNumberOfBytes = inputStream.transferTo(literalDataOutputStream);
            log.debug("Compressed {} bytes", compressedNumberOfBytes);
        } catch (IOException e) {
            throw new IllegalStateException("An error occurred during compression, " + e.getMessage(), e);
        }
    }
}
