package com.github.elkanuco.stream.encryption;

import java.util.Optional;

public class Configuration {

    static final int DEFAULT_BUFFER_SIZE = 2048;
    static final SymmetricKeyAlgorithm DEFAULT_SYMMETRIC_KEY_ALGORITHM_TAG = SymmetricKeyAlgorithm.AES_256;
    static final CompressionAlgorithm DEFAULT_COMPRESSION_ALGORITHM_TAG = CompressionAlgorithm.ZIP;
    static final Boolean DEFAULT_PROTECT_USING_AN_INTEGRITY_PACKET = Boolean.TRUE;

    final int bufferSize;
    final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    final CompressionAlgorithm compressionAlgorithm;
    final Boolean protectUsingAnIntegrityPacket;

    public Configuration() {
        this.bufferSize = DEFAULT_BUFFER_SIZE;
        this.symmetricKeyAlgorithm = DEFAULT_SYMMETRIC_KEY_ALGORITHM_TAG;
        this.compressionAlgorithm = DEFAULT_COMPRESSION_ALGORITHM_TAG;
        this.protectUsingAnIntegrityPacket = DEFAULT_PROTECT_USING_AN_INTEGRITY_PACKET;
    }

    public Configuration(final Integer bufferSize,
                         final SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                         final CompressionAlgorithm compressionAlgorithm,
                         final Boolean protectUsingAnIntegrityPacket) {
        this.bufferSize = Optional.ofNullable(bufferSize).orElse(DEFAULT_BUFFER_SIZE);
        this.symmetricKeyAlgorithm = Optional.ofNullable(symmetricKeyAlgorithm).orElse(DEFAULT_SYMMETRIC_KEY_ALGORITHM_TAG);
        this.compressionAlgorithm = Optional.ofNullable(compressionAlgorithm).orElse(DEFAULT_COMPRESSION_ALGORITHM_TAG);
        this.protectUsingAnIntegrityPacket = Optional.ofNullable(protectUsingAnIntegrityPacket).orElse(DEFAULT_PROTECT_USING_AN_INTEGRITY_PACKET);
    }
}
