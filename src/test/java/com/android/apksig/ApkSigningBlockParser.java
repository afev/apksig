package com.android.apksig;

import com.android.apksigner.HexEncoding;
import ru.CryptoPro.JCSP.JCSP;

import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * ApkSignerTool RSA
 * com.android.apksigner.ApkSigerTool
 * -Dkeytool.compat=true -Duse.cert.stub=true com.android.apksigner.ApkSignerTool sign --ks NONE --ks-key-alias android_2013 --ks-pass pass:CryptoCert -key-pass pass:CryptoCert --v3-signing-enabled false --v1-signing-enabled false --ks-type HDIMAGE --ks-provider-name JCSPRSA --ks-provider-class ru.CryptoPro.JCSP.JCSPRSA --provider-class ru.CryptoPro.JCSP.JCSPRSA --provider-pos 1 app.apk
 * ----
 * ApkSigTool_gost_sign
 * -Dkeytool.compat=true -Duse.cert.stub=true
 * com.android.apksigner.ApkSigerTool
 * sign --append-signature --ks NONE --ks-key-alias android_2013_gost --ks-pass pass:CryptoCert -key-pass pass:CryptoCert --v4-signing-enabled false --v3-signing-enabled false --v1-signing-enabled false --ks-type HDIMAGE --ks-provider-name JCSP --ks-provider-class ru.CryptoPro.JCSP.JCSP --provider-class ru.CryptoPro.JCSP.JCSP --provider-pos 1 app.apk
 * ----
 * ApkSigTool_gost_verify
 * -Dkeytool.compat=true -Duse.cert.stub=true
 * com.android.apksigner.ApkSigerTool
 * verify --verbose --print-certs --provider-class ru.CryptoPro.JCSP.JCSP --provider-pos 1 app.apk
 * ----
 * ApkSigningBlockParser
 * com.android.apksig.ApkSigningBlockParser
 * app.apk
 */

public class ApkSigningBlockParser {

    private static final byte[] MAGIC =
            "APK Sig Block 42".getBytes();

    private static final Map<Integer, String> SIG_ALGO_MAP = new HashMap<>();
    static {
        SIG_ALGO_MAP.put(0x0101, "SHA256withRSA");
        SIG_ALGO_MAP.put(0x0102, "SHA512withRSA");
        SIG_ALGO_MAP.put(0x0103, "SHA256withRSA");
        SIG_ALGO_MAP.put(0x0201, "SHA256withECDSA");
        SIG_ALGO_MAP.put(0x0202, "SHA512withECDSA");
        SIG_ALGO_MAP.put(0xff00, "GOST3411_2012_256withGOST3410_2012_256");
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: java ApkSigningBlockParser app.apk");
            return;
        }

        Security.addProvider(new JCSP());

        Path apkPath = Paths.get(args[0]);

        try (RandomAccessFile raf = new RandomAccessFile(apkPath.toFile(), "r");
             FileChannel channel = raf.getChannel()) {

            long fileSize = channel.size();

            long eocdSearchStart = Math.max(0, fileSize - 65536);
            ByteBuffer tail = ByteBuffer.allocate((int)(fileSize - eocdSearchStart));
            channel.read(tail, eocdSearchStart);
            tail.order(ByteOrder.LITTLE_ENDIAN);
            tail.flip();

            int eocdOffset = findEOCD(tail);
            if (eocdOffset < 0) throw new RuntimeException("EOCD not found");

            int cdOffset = tail.getInt(eocdOffset + 16);

            long footerOffset = cdOffset - 24;
            ByteBuffer footer = ByteBuffer.allocate(24);
            channel.read(footer, footerOffset);
            footer.order(ByteOrder.LITTLE_ENDIAN);
            footer.flip();

            long blockSize = footer.getLong();
            byte[] magic = new byte[16];
            footer.get(magic);

            if (!Arrays.equals(magic, MAGIC))
                throw new RuntimeException("Signing Block magic not found");

            long blockOffset = cdOffset - blockSize - 8;

            ByteBuffer block = ByteBuffer.allocate((int) blockSize);
            channel.read(block, blockOffset + 8);
            block.order(ByteOrder.LITTLE_ENDIAN);
            block.flip();

            while (block.remaining() > 24) {
                long len = block.getLong();
                int id = block.getInt();

                byte[] value = new byte[(int) (len - 4)];
                block.get(value);

                if (id == 0x7109871a || id == 0xf05368c0) {
                    System.out.printf("%n=== Signature Scheme: 0x%08x ===%n", id);
                    parseSignatureScheme(ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN));
                }
            }
        }
    }
    private static void parseSignatureScheme(ByteBuffer buf) {

        ByteBuffer signers = readLengthPrefixedSlice32(buf);

        while (signers.hasRemaining()) {
            ByteBuffer signer = readLengthPrefixedSlice32(signers);
            signer.order(ByteOrder.LITTLE_ENDIAN);
            System.out.println("Signer:");

            /* ============================================================
           1️⃣  SIGNED DATA  (ЭТО И ЕСТЬ ТО, ЧТО ПОДПИСЫВАЕТСЯ)
           ============================================================ */

            int signedDataLength = signer.getInt();

            if (signedDataLength > signer.remaining()) {
                throw new RuntimeException("signedData length beyond buffer");
            }

            byte[] signedDataBytes = new byte[signedDataLength];
            signer.get(signedDataBytes);

            // создаём отдельный буфер для парсинга signedData
            ByteBuffer signedData = ByteBuffer
                    .wrap(signedDataBytes)
                    .order(ByteOrder.LITTLE_ENDIAN);

            int digestAlgoId = 0;
            byte[] digestBytes = null;
            byte[] certBytes = null;
            int sigAlgoId = 0;
            byte[] sigBytes = null;
            byte[] pubKeyBytes = null;

            // --- digests ---
            ByteBuffer digests = readLengthPrefixedSlice32(signedData);
            while (digests.hasRemaining()) {
                ByteBuffer digest = readLengthPrefixedSlice32(digests);
                digestAlgoId = digest.getInt();
                int digestLen = digest.getInt();
                byte[] hash = new byte[digestLen];
                digest.get(hash);
                digestBytes = Arrays.copyOf(hash, digestLen);
                System.out.printf("  Digest Algorithm: 0x%08x%n", digestAlgoId);
                System.out.printf("  Digest bytes %s (%d)%n", HexEncoding.encode(digestBytes), digestBytes.length);
            }

            // --- certificates ---
            ByteBuffer certs = readLengthPrefixedSlice32(signedData);
            while (certs.hasRemaining()) {
                ByteBuffer cert = readLengthPrefixedSlice32(certs);
                certBytes = new byte[cert.remaining()];
                cert.get(certBytes);
                System.out.printf("  Certificate %s (%d bytes)%n", HexEncoding.encode(certBytes), certBytes.length);
            }

            // --- additional attributes ---
            if (signedData.hasRemaining()) {
                ByteBuffer attrs = readLengthPrefixedSlice32(signedData);
                while (attrs.hasRemaining()) {
                    ByteBuffer attr = readLengthPrefixedSlice32(attrs);
                    int attrId = attr.getInt();
                    System.out.printf("  Attribute ID: 0x%08x%n", attrId);
                }
            }

            // --- signatures ---
            ByteBuffer signatures = readLengthPrefixedSlice32(signer);
            while (signatures.hasRemaining()) {
                ByteBuffer sig = readLengthPrefixedSlice32(signatures);
                sigAlgoId = sig.getInt();
                int sigLen = sig.getInt();
                byte[] signature = new byte[sigLen];
                sig.get(signature);
                sigBytes = Arrays.copyOf(signature, sigLen);
                System.out.printf("  Signature Algorithm: 0x%08x%n", sigAlgoId);
                System.out.printf("  Signature bytes %s (%d)%n", HexEncoding.encode(sigBytes), sigBytes.length);
            }

            // --- public key ---
            ByteBuffer pubKey = readLengthPrefixedSlice32(signer);
            pubKeyBytes = new byte[pubKey.remaining()];
            pubKey.get(pubKeyBytes);
            System.out.printf("  Public Key %s (%d bytes)%n", HexEncoding.encode(pubKeyBytes), pubKeyBytes.length);

            try {
                System.out.println("verified: " + verifySignature(signedDataBytes, sigBytes, pubKeyBytes, sigAlgoId));
            } catch (Exception e) {
                 e.printStackTrace();
            }

        }
    }

    private static ByteBuffer readLengthPrefixedSlice32(ByteBuffer buf) {
        if (buf.remaining() < 4)
            throw new RuntimeException("Not enough data for uint32 length");

        int len = buf.getInt(); // uint32 LE

        if (len < 0)
            throw new RuntimeException("Negative length");

        if (buf.remaining() < len)
            throw new RuntimeException("Length beyond buffer");

        ByteBuffer slice = buf.slice();
        slice.limit(len);
        slice.order(ByteOrder.LITTLE_ENDIAN);

        buf.position(buf.position() + len);
        return slice;
    }

    private static ByteBuffer readLengthPrefixedSlice64(ByteBuffer buf) {
        if (buf.remaining() < 8)
            throw new RuntimeException("Not enough data for uint64 length");

        long len = buf.getLong();

        if (len > Integer.MAX_VALUE)
            throw new RuntimeException("Block too large");

        if (buf.remaining() < len)
            throw new RuntimeException("Length beyond buffer");

        ByteBuffer slice = buf.slice();
        slice.limit((int) len);
        slice.order(ByteOrder.LITTLE_ENDIAN);

        buf.position(buf.position() + (int) len);
        return slice;
    }

    private static int findEOCD(ByteBuffer buffer) {
        for (int i = buffer.limit() - 22; i >= 0; i--) {
            if (buffer.getInt(i) == 0x06054b50)
                return i;
        }
        return -1;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            sb.append(String.format("%02x", data[i]));
            if ((i + 1) % 32 == 0) sb.append("\n");
        }
        return sb.toString();
    }

    public static byte[] decode(byte[] data) {
        if (data.length == 0) {
            return new byte[0];
        }
        if (data.length % 2 != 0) {
            byte[] tmp = new byte[data.length + 1];
            tmp[0] = '0';
            System.arraycopy(data, 0, tmp, 1, data.length);
            data = tmp;
        }
        byte[] result = new byte[data.length / 2];
        for (int i = 0; i < data.length; i += 2) {
            int hi = Character.digit((char) data[i], 16);
            int lo = Character.digit((char) data[i + 1], 16);
            if (hi == -1 || lo == -1) {
                throw new IllegalArgumentException(
                        "Invalid hex character at position " + i
                );
            }
            result[i / 2] = (byte) ((hi << 4) + lo);
        }
        return result;
    }

    private static byte[] extractSignedDataBytes(ByteBuffer signerBlock) {
        // signerBlock — ByteBuffer на один signer внутри v2/v3 Signing Block
        signerBlock = signerBlock.slice(); // безопасная копия, не портим оригинал

        // readLengthPrefixedSlice32 возвращает ByteBuffer на signedData
        ByteBuffer signedData = readLengthPrefixedSlice32(signerBlock);

        // просто копируем все bytes из signedData в массив
        byte[] signedDataBytes = new byte[signedData.remaining()];
        signedData.get(signedDataBytes);
        return signedDataBytes;
    }

    public static boolean verifySignature(
            byte[] signedDataBytes,   // полный signedData
            byte[] signatureBytes,    // подпись из signature record
            byte[] publicKeyBytes,    // извлечённый public key
            int signatureAlgorithmId  // ID алгоритма
    ) throws Exception {

        String algoName = SIG_ALGO_MAP.get(signatureAlgorithmId);
        if (algoName == null) {
            throw new IllegalArgumentException(
                    String.format("Unknown signatureAlgorithmId: 0x%04x", signatureAlgorithmId));
        }

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        String keyAlg;

        if (algoName.contains("RSA")) {
            keyAlg = "RSA";
        } else if (algoName.contains("EC")) {
            keyAlg = "EC";
        } else if (algoName.contains("GOST")) {
            keyAlg = "GOST3410_2012_256";
        } else {
            throw new IllegalArgumentException("Unknown algorithm: " + algoName);
        }

        PublicKey pubKey = KeyFactory.getInstance(keyAlg).generatePublic(keySpec);

        Signature sig = Signature.getInstance(algoName);
        sig.initVerify(pubKey);
        sig.update(signedDataBytes); // <-- Важно: подписан весь signedData, а не digest
        return sig.verify(signatureBytes);
    }

}
