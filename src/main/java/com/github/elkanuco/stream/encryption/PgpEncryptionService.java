package com.github.elkanuco.stream.encryption;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

@Slf4j
class PgpEncryptionService {

    private final StreamUtils streamUtils;

    PgpEncryptionService() {
        this.streamUtils = new StreamUtils();
    }

    InputStream encrypt(final InputStream inputStream,
                        final PGPPublicKey pgpPublicKey,
                        final ExecutorService executorService,
                        final Configuration configuration
    ) {
        log.debug("Encrypting the stream");
        @SuppressWarnings("java:S2095") final PipedInputStream encryptionPipeInputStream = new PipedInputStream();
        final PipedOutputStream encryptionPipedOutputStream;
        encryptionPipedOutputStream = streamUtils.pipedOutputStream(encryptionPipeInputStream);
        final CompletableFuture<Void> compression = CompletableFuture
                .runAsync(
                        () -> encrypt(
                                inputStream,
                                pgpPublicKey,
                                encryptionPipedOutputStream,
                                configuration),
                        executorService
                );
        compression.whenComplete((aVoid, throwable) -> log.debug("Finished encryption"));
        return encryptionPipeInputStream;
    }

    private void encrypt(final InputStream inputStream,
                         final PGPPublicKey pgpPublicKey,
                         final PipedOutputStream encryptionPipedOutputStream,
                         final Configuration configuration) {

        try {
            final PGPEncryptedDataGenerator pgpEncryptedDataGenerator = buildPgpEncryptedDataGenerator(
                    pgpPublicKey,
                    configuration.symmetricKeyAlgorithm,
                    configuration.protectUsingAnIntegrityPacket.booleanValue());
            try (
                    inputStream;
                    encryptionPipedOutputStream;
                    final ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(encryptionPipedOutputStream);
                    final OutputStream encryptedOutputStream = pgpEncryptedDataGenerator.open(armoredOutputStream, new byte[configuration.bufferSize])
            ) {
                final long encryptedNumberOfBytes = inputStream.transferTo(encryptedOutputStream);
                log.debug("Encrypted {} bytes", encryptedNumberOfBytes);
            } finally {
                inputStream.close();
            }
        } catch (PGPException | IOException e) {
            throw new IllegalStateException("Unexpected error while encrypting.", e);
        }
    }

    private PGPEncryptedDataGenerator buildPgpEncryptedDataGenerator(final PGPPublicKey pgpPublicKey,
                                                                     final SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                                                     final boolean protectUsingAnIntegrityPacket) {
        final JcePGPDataEncryptorBuilder jcePGPDataEncryptorBuilder = buildJcePGPDataEncryptorBuilder(symmetricKeyAlgorithm, protectUsingAnIntegrityPacket);
        final JcePublicKeyKeyEncryptionMethodGenerator jcePublicKeyKeyEncryptionMethodGenerator = buildJcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey);
        final PGPEncryptedDataGenerator result = new PGPEncryptedDataGenerator(jcePGPDataEncryptorBuilder);
        result.addMethod(jcePublicKeyKeyEncryptionMethodGenerator);
        return result;
    }


    private JcePublicKeyKeyEncryptionMethodGenerator buildJcePublicKeyKeyEncryptionMethodGenerator(final PGPPublicKey encKey) {
        return new JcePublicKeyKeyEncryptionMethodGenerator(encKey)
                .setProvider("BC");
    }

    private JcePGPDataEncryptorBuilder buildJcePGPDataEncryptorBuilder(final SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                                                       final boolean protectUsingAnIntegrityPacket) {
        return new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm.getSymmetricKeyAlgorithmTag())
                .setWithIntegrityPacket(protectUsingAnIntegrityPacket)
                .setProvider("BC");
    }
}
