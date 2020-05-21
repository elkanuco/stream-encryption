package com.github.elkanuco.stream.encryption;

public enum CompressionAlgorithm {

    /**
     * No compression.
     */
    UNCOMPRESSED(0),

    /**
     * ZIP (RFC 1951) compression. Unwrapped DEFLATE.
     */
    ZIP(1),

    /**
     * ZLIB (RFC 1950) compression. DEFLATE with a wrapper for better error detection.
     */
    ZLIB(2),

    /**
     * BZIP2 compression. Better compression than ZIP but much slower to compress and decompress.
     */
    BZIP2(3);

    private final int compressionAlgorithmTag;

    CompressionAlgorithm(final int compressionAlgorithmTag) {
        this.compressionAlgorithmTag = compressionAlgorithmTag;
    }

    public int getCompressionAlgorithmTag() {
        return compressionAlgorithmTag;
    }
}