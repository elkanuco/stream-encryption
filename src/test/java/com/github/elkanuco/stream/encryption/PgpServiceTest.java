package com.github.elkanuco.stream.encryption;

import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.utility.RandomString;
import org.apache.commons.io.output.CountingOutputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
@ExtendWith(MockitoExtension.class)
class PgpServiceTest {
    static final int ONE_MEGABYTE = 1024 * 1024;
    private static byte[] privateKeyContent;
    private static byte[] publicKeyContent;

    private final ExecutorService executorService = Executors.newFixedThreadPool(4);


    @BeforeAll
    static void setup() throws Exception {
        exportKeyPair("enigma", "secret".toCharArray());
    }

    private static void exportKeyPair(
            final String identity,
            final char[] passPhrase)
            throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        try (
                final ByteArrayOutputStream privateKey = new ByteArrayOutputStream();
                final ByteArrayOutputStream publicKey = new ByteArrayOutputStream()
        ) {

            final ArmoredOutputStream privateKeyArmoredOutputStream = new ArmoredOutputStream(privateKey);
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(1024);
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            final PGPKeyPair jcaPGPKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());
            final PGPDigestCalculator pgpDigestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            final JcePBESecretKeyEncryptorBuilder jcePBESecretKeyEncryptorBuilder = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, pgpDigestCalculator).setProvider("BC");
            final PBESecretKeyEncryptor pbeSecretKeyEncryptor = jcePBESecretKeyEncryptorBuilder.build(passPhrase);
            final JcaPGPContentSignerBuilder jcaPGPContentSignerBuilder = new JcaPGPContentSignerBuilder(jcaPGPKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);
            final PGPSecretKey pgpSecretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, jcaPGPKeyPair, identity, pgpDigestCalculator, null, null, jcaPGPContentSignerBuilder, pbeSecretKeyEncryptor);
            pgpSecretKey.encode(privateKeyArmoredOutputStream);
            privateKeyArmoredOutputStream.close();
            privateKeyContent = privateKey.toByteArray();
            final ArmoredOutputStream publicKeyArmouredOutputStream = new ArmoredOutputStream(publicKey);
            final PGPPublicKey pgpSecretKeyPublicKey = pgpSecretKey.getPublicKey();
            pgpSecretKeyPublicKey.encode(publicKeyArmouredOutputStream);
            publicKeyArmouredOutputStream.close();
            publicKeyContent = publicKey.toByteArray();
        }
    }


    @ParameterizedTest
    @NullSource
    @ValueSource(ints = {512, 1024, 2048, 4096})
    void canEncryptFileWithDifferentBufferSizes(Integer bufferSize) throws IOException, PGPException, ExecutionException, InterruptedException {
        //given
        final Configuration configuration = new Configuration(bufferSize,
                Configuration.DEFAULT_SYMMETRIC_KEY_ALGORITHM_TAG,
                Configuration.DEFAULT_COMPRESSION_ALGORITHM_TAG,
                Configuration.DEFAULT_PROTECT_USING_AN_INTEGRITY_PACKET);
        final PgpService instance = new PgpService(configuration);
        final InputStream publicKey = publicKey();
        final InputStream secret = secret();
        //when
        final InputStream result = instance.encryptStream(secret, publicKey, executorService);
        //then
        final Path tempFile = tmpSecret();
        final CompletableFuture<Void> read = read(result, tempFile);
        read.get();
        Assertions.assertNotNull(result);
        compare(tempFile);
    }

    private Path tmpSecret() throws IOException {
        return Files.createTempFile("PgpServiceTest_", ".secret");
    }

    private InputStream secret() {
        return getClass().getResourceAsStream("/pgp/secret.txt");
    }

    private InputStream publicKey() {
        return new ByteArrayInputStream(publicKeyContent);
    }

    @ParameterizedTest
    @NullSource
    @EnumSource(value = SymmetricKeyAlgorithm.class)
    void canEncryptFileWithDifferentSymmetricAlgorithms(SymmetricKeyAlgorithm symmetricKeyAlgorithm) throws IOException, PGPException, InterruptedException, ExecutionException {
        //given
        final Configuration configuration = new Configuration(Configuration.DEFAULT_BUFFER_SIZE,
                symmetricKeyAlgorithm,
                Configuration.DEFAULT_COMPRESSION_ALGORITHM_TAG,
                Configuration.DEFAULT_PROTECT_USING_AN_INTEGRITY_PACKET);
        final PgpService instance = new PgpService(configuration);
        final InputStream publicKey = publicKey();
        final InputStream secret = secret();
        //when
        final InputStream result = instance.encryptStream(secret, publicKey, executorService);
        //then
        final Path tempFile = tmpSecret();
        final CompletableFuture<Void> read = read(result, tempFile);
        read.get();
        Assertions.assertNotNull(result);
        compare(tempFile);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(booleans = {true, false})
    void canEncryptFileWithDifferentIntegrityPacketUseFlag(Boolean protectWithAnIntegrityPacket) throws IOException, InterruptedException, PGPException, ExecutionException {
        //given
        final Configuration configuration = new Configuration(Configuration.DEFAULT_BUFFER_SIZE,
                Configuration.DEFAULT_SYMMETRIC_KEY_ALGORITHM_TAG,
                Configuration.DEFAULT_COMPRESSION_ALGORITHM_TAG,
                protectWithAnIntegrityPacket);
        final PgpService instance = new PgpService(configuration);
        final InputStream publicKey = publicKey();
        final InputStream secret = secret();
        //when
        final InputStream result = instance.encryptStream(secret, publicKey, executorService);
        //then
        final Path tempFile = tmpSecret();
        final CompletableFuture<Void> read = read(result, tempFile);
        read.get();
        Assertions.assertNotNull(result);
        compare(tempFile);
    }

    private void assertDone(CompletableFuture<Void> read, CompletableFuture<Void> compression, CompletableFuture<Void> encryption) {
        Assertions.assertTrue(List.of(compression, encryption, read).stream().allMatch(CompletableFuture::isDone));
    }

    @ParameterizedTest
    @NullSource
    @EnumSource(value = CompressionAlgorithm.class)
    void canEncryptFileWithDifferentCompressionAlgorithmFlag(CompressionAlgorithm compressionAlgorithm) throws IOException, InterruptedException, ExecutionException, PGPException {
        //given
        final Configuration configuration = new Configuration(Configuration.DEFAULT_BUFFER_SIZE,
                Configuration.DEFAULT_SYMMETRIC_KEY_ALGORITHM_TAG,
                compressionAlgorithm,
                Configuration.DEFAULT_PROTECT_USING_AN_INTEGRITY_PACKET);
        final PgpService instance = new PgpService(configuration);
        final InputStream publicKey = publicKey();
        final InputStream secret = secret();
        //when
        final InputStream result = instance.encryptStream(secret, publicKey, executorService);
        //then
        final Path tempFile = tmpSecret();
        final CompletableFuture<Void> read = read(result, tempFile);
        read.get();
        Assertions.assertNotNull(result);
        compare(tempFile);
    }

    @Test
    void canEncryptFileMockedStream() throws IOException, InterruptedException, PGPException, ExecutionException {
        //given
        final Configuration configuration = new Configuration();
        final PgpService instance = new PgpService(configuration);
        final InputStream publicKey = publicKey();
        final InputStream secret = mockAStream();
        //when
        final InputStream result = instance.encryptStream(secret, publicKey, executorService);
        //then
        Assertions.assertNotNull(result);

        final Path tempFile = tmpSecret();
        final CompletableFuture<Void> read = read(result, tempFile);
        read.get();
        //decrypt and compare
        final File file = tempFile.toFile();
        file.deleteOnExit();
        final byte[] bytes = decryptFile(new FileInputStream(file));
        Assertions.assertNotNull(bytes);
    }

    @Test
    void encryptInStream() throws IOException, PGPException {
        //given
        final boolean unstable = false;
        int targetSizeInMegaBytes = 250;
        final String baseString = "#12345678980azertyuiop$*€<>§§wxcvbn,;:=";

        final int bufferSize = 1024 * 8;
        final Configuration configuration = new Configuration(bufferSize,
                Configuration.DEFAULT_SYMMETRIC_KEY_ALGORITHM_TAG,
                Configuration.DEFAULT_COMPRESSION_ALGORITHM_TAG,
                Configuration.DEFAULT_PROTECT_USING_AN_INTEGRITY_PACKET);
        final PgpService instance = new PgpService(configuration);
        final byte[] baseStringBytes = baseString.concat("\n").getBytes(StandardCharsets.UTF_8);

        final int numberLines = repetition(baseStringBytes, targetSizeInMegaBytes);

        try (
                var secret = mockAStream(baseStringBytes, numberLines, unstable);
                var publicKey = publicKey();
                //when
                var encryptedStream = instance.encryptStream(secret, publicKey, executorService);
                var decryptedStream = decryptStream(encryptedStream)
        ) {
            //then
            int nLines = 0;
            String line;
            while ((line = decryptedStream.readLine()) != null) {
                unstableDelay(unstable, nLines);
                assertEquals(baseString, line);
                nLines++;
            }
            assertEquals(numberLines, nLines);
            log.info("Encrypted stream size is {} MB", encryptedStream.available() / ONE_MEGABYTE);
        }
    }

    private CompletableFuture<Void> read(final InputStream result, final Path tempFile) {
        return CompletableFuture.runAsync(() -> {
            try {
                //write the encrypted stream to a temp file
                try (final FileOutputStream fileOutputStream = new FileOutputStream(tempFile.toFile());
                     final BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream)) {
                    copy(result, bufferedOutputStream);
                }
            } catch (IOException e) {
                throw new IllegalStateException("Unable to pipe it in.", e);
            }
        });
    }

    private void compare(final Path tempFile) throws IOException, PGPException {
        //decrypt and compare
        final File file = tempFile.toFile();
        file.deleteOnExit();
        final byte[] bytes = decryptFile(new FileInputStream(file));
        assertEquals(new String(secret().readAllBytes(), StandardCharsets.UTF_8), new String(bytes, StandardCharsets.UTF_8));
    }

    private byte[] decryptFile(InputStream in) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();
        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData) encList.get(0);

        PGPSecretKey secretKey = readSecretKey(privateKey());
        final JcePublicKeyDataDecryptorFactoryBuilder jcePublicKeyDataDecryptorFactoryBuilder = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC");
        final PBESecretKeyDecryptor pbeSecretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("secret".toCharArray());
        final PGPPrivateKey pgpPrivateKey = secretKey.extractPrivateKey(pbeSecretKeyDecryptor);
        final PublicKeyDataDecryptorFactory build = jcePublicKeyDataDecryptorFactoryBuilder.build(pgpPrivateKey);
        try (InputStream clear = encP.getDataStream(build)) {
            final JcaPGPObjectFactory rootJcaPGPObjectFactory = new JcaPGPObjectFactory(clear);
            Object o = rootJcaPGPObjectFactory.nextObject();
            if (o instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) o;
                try (final InputStream dataStream = cData.getDataStream()) {
                    final JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(dataStream);
                    o = jcaPGPObjectFactory.nextObject();
                    return read((PGPLiteralData) o);
                }
            }
            return read((PGPLiteralData) o);
        }
    }

    private InputStream privateKey() {
        return new ByteArrayInputStream(privateKeyContent);
    }

    private BufferedReader decryptStream(InputStream encryptedStream) throws IOException, PGPException {
        InputStream decryptedStream = PGPUtil.getDecoderStream(encryptedStream);

        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(decryptedStream);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();
        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData) encList.get(0);

        PGPSecretKey secretKey = readSecretKey(privateKey());
        final JcePublicKeyDataDecryptorFactoryBuilder jcePublicKeyDataDecryptorFactoryBuilder = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC");
        final PBESecretKeyDecryptor pbeSecretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("secret".toCharArray());
        final PGPPrivateKey pgpPrivateKey = secretKey.extractPrivateKey(pbeSecretKeyDecryptor);
        final PublicKeyDataDecryptorFactory build = jcePublicKeyDataDecryptorFactoryBuilder.build(pgpPrivateKey);
        InputStream clear = encP.getDataStream(build);
        final JcaPGPObjectFactory rootJcaPGPObjectFactory = new JcaPGPObjectFactory(clear);
        Object o = rootJcaPGPObjectFactory.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) o;
            final InputStream dataStream = cData.getDataStream();
            final JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(dataStream);
            o = jcaPGPObjectFactory.nextObject();
            return new BufferedReader(new InputStreamReader(((PGPLiteralData) o).getInputStream(), StandardCharsets.UTF_8));

        }
        return new BufferedReader(new InputStreamReader(((PGPLiteralData) o).getInputStream(), StandardCharsets.UTF_8));
    }


    private byte[] read(final PGPLiteralData o) throws IOException {
        try (final InputStream unc = o.getInputStream()) {
            return unc.readAllBytes();
        }

    }

    private PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        try (final InputStream decoderStream = PGPUtil.getDecoderStream(input)) {
            final JcaKeyFingerprintCalculator keyFingerPrintCalculator = new JcaKeyFingerprintCalculator();
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(decoderStream, keyFingerPrintCalculator);
            PGPSecretKeyRing keyRing = pgpSec.getKeyRings().next();
            return keyRing.getSecretKeys().next();
        }

    }

    private PipedInputStream mockAStream() throws IOException {
        PipedInputStream pipedInputStream = new PipedInputStream();
        PipedOutputStream pipedOutputStream = new PipedOutputStream(pipedInputStream);
        CompletableFuture.runAsync(() -> {
            try (pipedOutputStream) {
                int numberOfWrites = 100_000; // 64MB
                IntStream.range(0, numberOfWrites).forEach(ignored ->
                {
                    try {
                        pipedOutputStream.write(RandomString.make(666).getBytes());
                    } catch (IOException e) {
                        throw new IllegalStateException("Unable to mock stream", e);
                    }
                });
            } catch (IOException e) {
                throw new IllegalStateException("Unable to mock stream", e);
            }
        });
        return pipedInputStream;

    }

    long copy(InputStream from, OutputStream to) throws IOException {
        Objects.requireNonNull(from);
        Objects.requireNonNull(to);
        byte[] buf = new byte[8192];
        long total = 0;
        while (true) {
            int r = from.read(buf);
            if (r == -1) {
                break;
            }
            to.write(buf, 0, r);
            total += r;
        }
        return total;
    }

    private InputStream mockAStream(byte[] baseStringBytes, int repetition, @SuppressWarnings("SameParameterValue") boolean unstable) {
        var pipedInputStream = new PipedInputStream();
        CompletableFuture.runAsync(() -> {
            try (CountingOutputStream outputStream = new CountingOutputStream(new PipedOutputStream(pipedInputStream))) {
                for (int i = 0; i < repetition; i++) {
                    unstableDelay(unstable, i);
                    if (outputStream.getCount() % ONE_MEGABYTE < baseStringBytes.length) {
                        log.info("Written {}MB streamed", outputStream.getCount() / ONE_MEGABYTE);
                    }
                    outputStream.write(baseStringBytes);
                }
                log.info("Produced {} MB streamed", outputStream.getCount() / ONE_MEGABYTE);
            } catch (IOException e) {
                throw new IllegalStateException("Unable to mock stream", e);
            }
        });
        return pipedInputStream;
    }

    private void unstableDelay(boolean unstable, int i) {
        try {
            if (unstable && i % ThreadLocalRandom.current().nextInt(200, 5_000) == 0)
                //Simulate unstable stream
                TimeUnit.MILLISECONDS.sleep(ThreadLocalRandom.current().nextInt(30));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private int repetition(byte[] baseStringBytes, int targetSizeInMegaBytes) {
        return (targetSizeInMegaBytes * ONE_MEGABYTE / baseStringBytes.length) + 1;
    }
}

