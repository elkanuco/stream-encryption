package com.github.elkanuco.stream.encryption;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.InputStream;
import java.security.Security;
import java.util.concurrent.ExecutorService;

@Slf4j
public class PgpService {

    private final PgpUtils pgpUtils;
    private final Configuration configuration;

    public PgpService(final Configuration configuration) {
        this.configuration = configuration;
        this.pgpUtils = new PgpUtils();
    }

    /**
     * Compress and encrypt a stream using PGP.
     *
     * @param inputStream     the stream to encrypt
     * @param publicKeyStream the public key stream
     * @return an wrapped stream encrypted; this must be closed
     */
    public InputStream encryptStream(
            final InputStream inputStream,
            final InputStream publicKeyStream,
            final ExecutorService executorService
    ) {
        log.debug("Adding provider to java's security manager.");
        final BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);

        log.debug("Reading publick key.");
        final PGPPublicKey pgpPublicKey = pgpUtils.readPublicKey(publicKeyStream);

        return pgpUtils.encryptFile(inputStream,
                pgpPublicKey,
                executorService,
                configuration);
    }


}
