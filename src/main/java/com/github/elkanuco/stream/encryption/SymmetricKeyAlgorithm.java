package com.github.elkanuco.stream.encryption;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

public enum SymmetricKeyAlgorithm {
    //NULL(SymmetricKeyAlgorithmTags.NULL),        // Plaintext or unencrypted data
    IDEA(SymmetricKeyAlgorithmTags.IDEA),        // IDEA [IDEA]
    TRIPLE_DES(SymmetricKeyAlgorithmTags.TRIPLE_DES),  // Triple-DES (DES-EDE, as per spec -168 bit key derived from 192)
    CAST5(SymmetricKeyAlgorithmTags.CAST5),       // CAST5 (128 bit key, as per RFC 2144)
    BLOWFISH(SymmetricKeyAlgorithmTags.BLOWFISH),    // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
    //SAFER(SymmetricKeyAlgorithmTags.SAFER),       // SAFER-SK128 (13 rounds) [SAFER]
    DES(SymmetricKeyAlgorithmTags.DES),         // Reserved for DES/SK
    AES_128(SymmetricKeyAlgorithmTags.AES_128),     // Reserved for AES with 128-bit key
    AES_192(SymmetricKeyAlgorithmTags.AES_192),     // Reserved for AES with 192-bit key
    AES_256(SymmetricKeyAlgorithmTags.AES_256),     // Reserved for AES with 256-bit key
    TWOFISH(SymmetricKeyAlgorithmTags.TWOFISH),    // Reserved for Twofish
    CAMELLIA_128(SymmetricKeyAlgorithmTags.CAMELLIA_128),    // Reserved for Camellia with 128-bit key
    CAMELLIA_192(SymmetricKeyAlgorithmTags.CAMELLIA_192),    // Reserved for Camellia with 192-bit key
    CAMELLIA_256(SymmetricKeyAlgorithmTags.CAMELLIA_256);    // Reserved for Camellia with 256-bit key

    private final int symmetricKeyAlgorithmTag;

    SymmetricKeyAlgorithm(int symmetricKeyAlgorithmTag) {
        this.symmetricKeyAlgorithmTag = symmetricKeyAlgorithmTag;
    }

    int getSymmetricKeyAlgorithmTag() {
        return symmetricKeyAlgorithmTag;
    }
}
