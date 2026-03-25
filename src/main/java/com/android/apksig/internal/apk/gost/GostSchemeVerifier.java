package com.android.apksig.internal.apk.gost;

import com.android.apksig.ApkVerifier;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;

import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.SignatureInfo;

import com.android.apksig.internal.apk.v2.V2SchemeConstants;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate;
import com.android.apksig.internal.util.X509CertificateUtils;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.RunnablesExecutor;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import static com.android.apksig.Constants.MAX_APK_SIGNERS;

public class GostSchemeVerifier {

    public static ApkSigningBlockUtils.Result verify(
            RunnablesExecutor executor,
            DataSource apk,
            ApkUtils.ZipSections zipSections,
            Map<Integer, String> supportedApkSigSchemeNames,
            Set<Integer> foundSigSchemeIds,
            int minSdkVersion,
            int maxSdkVersion)
            throws IOException, ApkFormatException, NoSuchAlgorithmException,
            ApkSigningBlockUtils.SignatureNotFoundException {
        ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(
                ApkSigningBlockUtils.VERSION_APK_GOST_SIGNATURE_SCHEME);
        SignatureInfo signatureInfo =
                ApkSigningBlockUtils.findSignature(apk, zipSections,
                        GostSchemeConstants.APK_SIGNATURE_GOST_SCHEME_BLOCK_ID, result);

        DataSource beforeApkSigningBlock = apk.slice(0, signatureInfo.apkSigningBlockOffset);
        DataSource centralDir =
                apk.slice(
                        signatureInfo.centralDirOffset,
                        signatureInfo.eocdOffset - signatureInfo.centralDirOffset);
        ByteBuffer eocd = signatureInfo.eocd;

        verify(executor,
                beforeApkSigningBlock,
                signatureInfo.signatureBlock,
                centralDir,
                eocd,
                supportedApkSigSchemeNames,
                foundSigSchemeIds,
                minSdkVersion,
                maxSdkVersion,
                result);
        return result;
    }

    private static void verify(
            RunnablesExecutor executor,
            DataSource beforeApkSigningBlock,
            ByteBuffer apkSignatureGostSchemeBlock,
            DataSource centralDir,
            ByteBuffer eocd,
            Map<Integer, String> supportedApkSigSchemeNames,
            Set<Integer> foundSigSchemeIds,
            int minSdkVersion,
            int maxSdkVersion,
            ApkSigningBlockUtils.Result result)
            throws IOException, NoSuchAlgorithmException {
        Set<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<>(1);
        parseSigners(
                apkSignatureGostSchemeBlock,
                contentDigestsToVerify,
                supportedApkSigSchemeNames,
                foundSigSchemeIds,
                minSdkVersion,
                maxSdkVersion,
                result);
        if (result.containsErrors()) {
            return;
        }
        ApkSigningBlockUtils.verifyIntegrity(
                executor, beforeApkSigningBlock, centralDir, eocd, contentDigestsToVerify, result);
        if (!result.containsErrors()) {
            result.verified = true;
        }
    }

    public static void parseSigners(
            ByteBuffer apkSignatureGostSchemeBlock,
            Set<ContentDigestAlgorithm> contentDigestsToVerify,
            Map<Integer, String> supportedApkSigSchemeNames,
            Set<Integer> foundApkSigSchemeIds,
            int minSdkVersion,
            int maxSdkVersion,
            ApkSigningBlockUtils.Result result) throws NoSuchAlgorithmException {
        ByteBuffer signers;
        try {
            signers = ApkSigningBlockUtils.getLengthPrefixedSlice(apkSignatureGostSchemeBlock);
        } catch (ApkFormatException e) {
            result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_SIGNERS);
            return;
        }
        if (!signers.hasRemaining()) {
            result.addError(ApkVerifier.Issue.V2_SIG_NO_SIGNERS);
            return;
        }

        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to obtain X.509 CertificateFactory", e);
        }
        int signerCount = 0;
        while (signers.hasRemaining()) {
            int signerIndex = signerCount;
            signerCount++;
            ApkSigningBlockUtils.Result.SignerInfo signerInfo =
                    new ApkSigningBlockUtils.Result.SignerInfo();
            signerInfo.index = signerIndex;
            result.signers.add(signerInfo);
            try {
                ByteBuffer signer = ApkSigningBlockUtils.getLengthPrefixedSlice(signers);
                parseSigner(
                        signer,
                        certFactory,
                        signerInfo,
                        contentDigestsToVerify,
                        supportedApkSigSchemeNames,
                        foundApkSigSchemeIds,
                        minSdkVersion,
                        maxSdkVersion);
            } catch (ApkFormatException | BufferUnderflowException e) {
                signerInfo.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_SIGNER);
                return;
            }
        }
        if (signerCount > MAX_APK_SIGNERS) {
            result.addError(ApkVerifier.Issue.V2_SIG_MAX_SIGNATURES_EXCEEDED, MAX_APK_SIGNERS, signerCount);
        }
    }

    private static void parseSigner(
            ByteBuffer signerBlock,
            CertificateFactory certFactory,
            ApkSigningBlockUtils.Result.SignerInfo result,
            Set<ContentDigestAlgorithm> contentDigestsToVerify,
            Map<Integer, String> supportedApkSigSchemeNames,
            Set<Integer> foundApkSigSchemeIds,
            int minSdkVersion,
            int maxSdkVersion) throws ApkFormatException, NoSuchAlgorithmException {
        ByteBuffer signedData = ApkSigningBlockUtils.getLengthPrefixedSlice(signerBlock);
        byte[] signedDataBytes = new byte[signedData.remaining()];
        signedData.get(signedDataBytes);
        signedData.flip();
        result.signedData = signedDataBytes;

        ByteBuffer signatures = ApkSigningBlockUtils.getLengthPrefixedSlice(signerBlock);
        byte[] publicKeyBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(signerBlock);

        // Parse the signatures block and identify supported signatures
        int signatureCount = 0;
        List<ApkSigningBlockUtils.SupportedSignature> supportedSignatures = new ArrayList<>(1);
        while (signatures.hasRemaining()) {
            signatureCount++;
            try {
                ByteBuffer signature = ApkSigningBlockUtils.getLengthPrefixedSlice(signatures);
                int sigAlgorithmId = signature.getInt();
                byte[] sigBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(signature);
                result.signatures.add(
                        new ApkSigningBlockUtils.Result.SignerInfo.Signature(
                                sigAlgorithmId, sigBytes));
                SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(sigAlgorithmId);
                if (signatureAlgorithm == null) {
                    result.addWarning(ApkVerifier.Issue.V2_SIG_UNKNOWN_SIG_ALGORITHM, sigAlgorithmId);
                    continue;
                }
                supportedSignatures.add(
                        new ApkSigningBlockUtils.SupportedSignature(signatureAlgorithm, sigBytes));
            } catch (ApkFormatException | BufferUnderflowException e) {
                result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_SIGNATURE, signatureCount);
                return;
            }
        }
        if (result.signatures.isEmpty()) {
            result.addError(ApkVerifier.Issue.V2_SIG_NO_SIGNATURES);
            return;
        }

        // Verify signatures over signed-data block using the public key
        List<ApkSigningBlockUtils.SupportedSignature> signaturesToVerify = null;
        try {
            signaturesToVerify =
                    ApkSigningBlockUtils.getSignaturesToVerify(
                            supportedSignatures, minSdkVersion, maxSdkVersion);
        } catch (ApkSigningBlockUtils.NoSupportedSignaturesException e) {
            result.addError(ApkVerifier.Issue.V2_SIG_NO_SUPPORTED_SIGNATURES, e);
            return;
        }
        for (ApkSigningBlockUtils.SupportedSignature signature : signaturesToVerify) {
            SignatureAlgorithm signatureAlgorithm = signature.algorithm;
            String jcaSignatureAlgorithm =
                    signatureAlgorithm.getJcaSignatureAlgorithmAndParams().getFirst();
            AlgorithmParameterSpec jcaSignatureAlgorithmParams =
                    signatureAlgorithm.getJcaSignatureAlgorithmAndParams().getSecond();
            String keyAlgorithm = signatureAlgorithm.getJcaKeyAlgorithm();
            PublicKey publicKey;
            try {
                publicKey =
                        KeyFactory.getInstance(keyAlgorithm).generatePublic(
                                new X509EncodedKeySpec(publicKeyBytes, "TRUSTED")); // trust public key in strengthened key control mode
            } catch (Exception e) {
                result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_PUBLIC_KEY, e);
                return;
            }
            try {
                Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
                sig.initVerify(publicKey);
                if (jcaSignatureAlgorithmParams != null) {
                    sig.setParameter(jcaSignatureAlgorithmParams);
                }
                signedData.position(0);
                sig.update(signedData);
                byte[] sigBytes = signature.signature;
                if (!sig.verify(sigBytes)) {
                    result.addError(ApkVerifier.Issue.V2_SIG_DID_NOT_VERIFY, signatureAlgorithm);
                    return;
                }
                result.verifiedSignatures.put(signatureAlgorithm, sigBytes);
                contentDigestsToVerify.add(signatureAlgorithm.getContentDigestAlgorithm());
            } catch (InvalidKeyException | InvalidAlgorithmParameterException
                     | SignatureException e) {
                result.addError(ApkVerifier.Issue.V2_SIG_VERIFY_EXCEPTION, signatureAlgorithm, e);
                return;
            }
        }

        // At least one signature over signedData has verified. We can now parse signed-data.
        signedData.position(0);
        ByteBuffer digests = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
        ByteBuffer certificates = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
        ByteBuffer additionalAttributes = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);

        // Parse the certificates block
        int certificateIndex = -1;
        while (certificates.hasRemaining()) {
            certificateIndex++;
            byte[] encodedCert = ApkSigningBlockUtils.readLengthPrefixedByteArray(certificates);
            X509Certificate certificate;
            try {
                certificate = X509CertificateUtils.generateCertificate(encodedCert, certFactory);
            } catch (CertificateException e) {
                result.addError(
                        ApkVerifier.Issue.V2_SIG_MALFORMED_CERTIFICATE,
                        certificateIndex,
                        certificateIndex + 1,
                        e);
                return;
            }
            // Wrap the cert so that the result's getEncoded returns exactly the original encoded
            // form. Without this, getEncoded may return a different form from what was stored in
            // the signature. This is because some X509Certificate(Factory) implementations
            // re-encode certificates.
            certificate = new GuaranteedEncodedFormX509Certificate(certificate, encodedCert);
            result.certs.add(certificate);
        }

        if (result.certs.isEmpty()) {
            result.addError(ApkVerifier.Issue.V2_SIG_NO_CERTIFICATES);
            return;
        }
        X509Certificate mainCertificate = result.certs.get(0);
        byte[] certificatePublicKeyBytes;
        try {
            certificatePublicKeyBytes = ApkSigningBlockUtils.encodePublicKey(
                    mainCertificate.getPublicKey());
        } catch (InvalidKeyException e) {
            System.out.println("Caught an exception encoding the public key: " + e);
            e.printStackTrace();
            certificatePublicKeyBytes = mainCertificate.getPublicKey().getEncoded();
        }
        if (!Arrays.equals(publicKeyBytes, certificatePublicKeyBytes)) {
            result.addError(
                    ApkVerifier.Issue.V2_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,
                    ApkSigningBlockUtils.toHex(certificatePublicKeyBytes),
                    ApkSigningBlockUtils.toHex(publicKeyBytes));
            return;
        }

        // Parse the digests block
        int digestCount = 0;
        while (digests.hasRemaining()) {
            digestCount++;
            try {
                ByteBuffer digest = ApkSigningBlockUtils.getLengthPrefixedSlice(digests);
                int sigAlgorithmId = digest.getInt();
                byte[] digestBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(digest);
                result.contentDigests.add(
                        new ApkSigningBlockUtils.Result.SignerInfo.ContentDigest(
                                sigAlgorithmId, digestBytes));
            } catch (ApkFormatException | BufferUnderflowException e) {
                result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_DIGEST, digestCount);
                return;
            }
        }

        List<Integer> sigAlgsFromSignaturesRecord = new ArrayList<>(result.signatures.size());
        for (ApkSigningBlockUtils.Result.SignerInfo.Signature signature : result.signatures) {
            sigAlgsFromSignaturesRecord.add(signature.getAlgorithmId());
        }
        List<Integer> sigAlgsFromDigestsRecord = new ArrayList<>(result.contentDigests.size());
        for (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest digest : result.contentDigests) {
            sigAlgsFromDigestsRecord.add(digest.getSignatureAlgorithmId());
        }

        if (!sigAlgsFromSignaturesRecord.equals(sigAlgsFromDigestsRecord)) {
            result.addError(
                    ApkVerifier.Issue.V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS,
                    sigAlgsFromSignaturesRecord,
                    sigAlgsFromDigestsRecord);
            return;
        }

        // Parse the additional attributes block.
        int additionalAttributeCount = 0;
        Set<Integer> supportedApkSigSchemeIds = supportedApkSigSchemeNames.keySet();
        Set<Integer> supportedExpectedApkSigSchemeIds = new HashSet<>(1);
        while (additionalAttributes.hasRemaining()) {
            additionalAttributeCount++;
            try {
                ByteBuffer attribute =
                        ApkSigningBlockUtils.getLengthPrefixedSlice(additionalAttributes);
                int id = attribute.getInt();
                byte[] value = ByteBufferUtils.toByteArray(attribute);
                result.additionalAttributes.add(
                        new ApkSigningBlockUtils.Result.SignerInfo.AdditionalAttribute(id, value));
                switch (id) {
                    case V2SchemeConstants.STRIPPING_PROTECTION_ATTR_ID:
                        // stripping protection added when signing with a newer scheme
                        int foundId = ByteBuffer.wrap(value).order(
                                ByteOrder.LITTLE_ENDIAN).getInt();
                        if (supportedApkSigSchemeIds.contains(foundId)) {
                            supportedExpectedApkSigSchemeIds.add(foundId);
                        } else {
                            result.addWarning(
                                    ApkVerifier.Issue.V2_SIG_UNKNOWN_APK_SIG_SCHEME_ID, result.index, foundId);
                        }
                        break;
                    default:
                        result.addWarning(ApkVerifier.Issue.V2_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE, id);
                }
            } catch (ApkFormatException | BufferUnderflowException e) {
                result.addError(
                        ApkVerifier.Issue.V2_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE, additionalAttributeCount);
                return;
            }
        }

        // make sure that all known IDs indicated in stripping protection have already verified
        for (int id : supportedExpectedApkSigSchemeIds) {
            if (!foundApkSigSchemeIds.contains(id)) {
                String apkSigSchemeName = supportedApkSigSchemeNames.get(id);
                result.addError(
                        ApkVerifier.Issue.V2_SIG_MISSING_APK_SIG_REFERENCED,
                        result.index,
                        apkSigSchemeName);
            }
        }
    }

}
