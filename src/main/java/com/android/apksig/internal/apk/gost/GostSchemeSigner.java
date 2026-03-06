package com.android.apksig.internal.apk.gost;

import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;

import com.android.apksig.internal.util.Pair;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.RunnablesExecutor;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.android.apksig.internal.apk.ApkSigningBlockUtils.*;
import static com.android.apksig.internal.apk.ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes;

public class GostSchemeSigner {

    public static List<SignatureAlgorithm> getSuggestedSignatureAlgorithms(PublicKey signingKey,
        int minSdkVersion) throws InvalidKeyException {
        String keyAlgorithm = signingKey.getAlgorithm();
        if ("GOST3410_2012_256".equalsIgnoreCase(keyAlgorithm)) {
            return Collections.singletonList(SignatureAlgorithm.GOST2012_WITH_GOST2012256);
        }
        else {
            throw new InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
        }
    }

    public static ApkSigningBlockUtils.SigningSchemeBlockAndDigests
        generateApkSignatureSchemeBlock(
            RunnablesExecutor executor,
            DataSource beforeCentralDir,
            DataSource centralDir,
            DataSource eocd,
            List<ApkSigningBlockUtils.SignerConfig> signerConfigs)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException,
            SignatureException {
        Pair<List<ApkSigningBlockUtils.SignerConfig>, Map<ContentDigestAlgorithm, byte[]>> digestInfo =
                ApkSigningBlockUtils.computeContentDigests(
                        executor, beforeCentralDir, centralDir, eocd, signerConfigs);
        return new ApkSigningBlockUtils.SigningSchemeBlockAndDigests(
                generateApkSignatureSchemeBlock(
                        digestInfo.getFirst(), digestInfo.getSecond()),
                digestInfo.getSecond());
    }

    private static Pair<byte[], Integer> generateApkSignatureSchemeBlock(
            List<ApkSigningBlockUtils.SignerConfig> signerConfigs,
            Map<ContentDigestAlgorithm, byte[]> contentDigests)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // FORMAT:
        // * length-prefixed sequence of length-prefixed signer blocks.

        if (signerConfigs.size() > 1) {
            throw new IllegalArgumentException(
                    "APK Signature Scheme only supports a maximum of 1, "
                            + signerConfigs.size() + " provided");
        }

        List<byte[]> signerBlocks = new ArrayList<>(signerConfigs.size());
        int signerNumber = 0;
        for (ApkSigningBlockUtils.SignerConfig signerConfig : signerConfigs) {
            signerNumber++;
            byte[] signerBlock;
            try {
                signerBlock = generateSignerBlock(signerConfig, contentDigests);
            } catch (InvalidKeyException e) {
                throw new InvalidKeyException("Signer #" + signerNumber + " failed", e);
            } catch (SignatureException e) {
                throw new SignatureException("Signer #" + signerNumber + " failed", e);
            }
            signerBlocks.add(signerBlock);
        }

        return Pair.of(
                encodeAsSequenceOfLengthPrefixedElements(
                        new byte[][] {
                                encodeAsSequenceOfLengthPrefixedElements(signerBlocks),
                        }),
                GostSchemeConstants.APK_SIGNATURE_GOST_SCHEME_BLOCK_ID);
    }

    private static byte[] generateSignerBlock(
            ApkSigningBlockUtils.SignerConfig signerConfig,
            Map<ContentDigestAlgorithm, byte[]> contentDigests)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (signerConfig.certificates.isEmpty()) {
            throw new SignatureException("No certificates configured for signer");
        }
        PublicKey publicKey = signerConfig.certificates.get(0).getPublicKey();

        byte[] encodedPublicKey = encodePublicKey(publicKey);

        SignatureSchemeBlock.SignedData signedData = new SignatureSchemeBlock.SignedData();
        try {
            signedData.certificates = encodeCertificates(signerConfig.certificates);
        } catch (CertificateEncodingException e) {
            throw new SignatureException("Failed to encode certificates", e);
        }

        List<Pair<Integer, byte[]>> digests =
                new ArrayList<>(signerConfig.signatureAlgorithms.size());
        for (SignatureAlgorithm signatureAlgorithm : signerConfig.signatureAlgorithms) {
            ContentDigestAlgorithm contentDigestAlgorithm =
                    signatureAlgorithm.getContentDigestAlgorithm();
            byte[] contentDigest = contentDigests.get(contentDigestAlgorithm);
            if (contentDigest == null) {
                throw new RuntimeException(
                        contentDigestAlgorithm
                                + " content digest for "
                                + signatureAlgorithm
                                + " not computed");
            }
            digests.add(Pair.of(signatureAlgorithm.getId(), contentDigest));
        }
        signedData.digests = digests;
        signedData.additionalAttributes = new byte[0];

        SignatureSchemeBlock.Signer signer = new SignatureSchemeBlock.Signer();
        // FORMAT:
        // * length-prefixed sequence of length-prefixed digests:
        //   * uint32: signature algorithm ID
        //   * length-prefixed bytes: digest of contents
        // * length-prefixed sequence of certificates:
        //   * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
        // * length-prefixed sequence of length-prefixed additional attributes:
        //   * uint32: ID
        //   * (length - 4) bytes: value

        signer.signedData =
                encodeAsSequenceOfLengthPrefixedElements(
                        new byte[][] {
                                encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                                        signedData.digests),
                                encodeAsSequenceOfLengthPrefixedElements(signedData.certificates),
                                signedData.additionalAttributes,
                                new byte[0],
                        });
        signer.publicKey = encodedPublicKey;
        signer.signatures = new ArrayList<>();
        signer.signatures =
                ApkSigningBlockUtils.generateSignaturesOverData(signerConfig, signer.signedData);

        // FORMAT:
        // * length-prefixed signed data
        // * length-prefixed sequence of length-prefixed signatures:
        //   * uint32: signature algorithm ID
        //   * length-prefixed bytes: signature of signed data
        // * length-prefixed bytes: public key (X.509 SubjectPublicKeyInfo, ASN.1 DER encoded)
        return encodeAsSequenceOfLengthPrefixedElements(
                new byte[][] {
                        signer.signedData,
                        encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                                signer.signatures),
                        signer.publicKey,
                });
    }

    private static final class SignatureSchemeBlock {
        private static final class Signer {
            public byte[] signedData;
            public List<Pair<Integer, byte[]>> signatures;
            public byte[] publicKey;
        }

        private static final class SignedData {
            public List<Pair<Integer, byte[]>> digests;
            public List<byte[]> certificates;
            public byte[] additionalAttributes;
        }
    }

}
