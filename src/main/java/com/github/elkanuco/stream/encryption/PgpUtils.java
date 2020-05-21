package com.github.elkanuco.stream.encryption;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.InputStream;
import java.util.concurrent.ExecutorService;

/**
 * @see https://github.com/bcgit/bc-java
 */
@Slf4j
class PgpUtils {
    private final PgpCompressionService pgpCompressionService;
    private final PgpEncryptionService pgpEncryptionService;

    PgpUtils() {
        this.pgpCompressionService = new PgpCompressionService();
        this.pgpEncryptionService = new PgpEncryptionService();
    }

    InputStream encryptFile(
            final InputStream inputStream,
            final PGPPublicKey pgpPublicKey,
            final ExecutorService executorService,
            final Configuration configuration
    ) {
        log.debug("Starting PGP encryption.");

        final InputStream compressionStream = pgpCompressionService.compress(
                inputStream,
                executorService,
                configuration
        );

        return pgpEncryptionService.encrypt(
                compressionStream,
                pgpPublicKey,
                executorService,
                configuration
        );
    }

    PGPPublicKey readPublicKey(InputStream publicKey) {
        try (
                publicKey;
                final InputStream decoderStream = PGPUtil.getDecoderStream(publicKey)
        ) {
            JcaKeyFingerprintCalculator keyFingerPrintCalculator = new JcaKeyFingerprintCalculator();
            PGPPublicKeyRingCollection pgpPublicKeyRings = new PGPPublicKeyRingCollection(decoderStream, keyFingerPrintCalculator);
            return pgpPublicKeyRings.getKeyRings().next().getPublicKeys().next();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to read public key for PGP encryption.", e);
        }
    }


}
