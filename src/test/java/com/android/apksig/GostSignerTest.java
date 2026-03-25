package com.android.apksig;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.internal.util.Resources;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;

import com.google.common.io.Files;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.JCSPRSA;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

@RunWith(JUnit4.class)
public class GostSignerTest {

    // Append GOST signature using Java CSP by GOST key android_2013_gost:
    // java -Dkeytool.compat=true -Duse.cert.stub=true com.android.apksigner.ApkSignerTool sign \
    // --append-signature --v4-signing-enabled false --v3-signing-enabled false --v2-signing-enabled false --gost-signing-enabled true --v1-signing-enabled false --stamp-timestamp-enabled false \
    // --ks NONE --ks-type HDIMAGE --ks-key-alias android_2013_gost --ks-pass pass:CryptoCert -key-pass pass:CryptoCert --ks-provider-name JCSP --ks-provider-class ru.CryptoPro.JCSP.JCSP --provider-class ru.CryptoPro.JCSP.JCSP --provider-pos 1 \
    // app.apk

    // ReSign V4 (update separate signature after source v4 has been broken) using Java CSP RSA by RSA key android_2013:
    // java -Dkeytool.compat=true -Duse.cert.stub=true com.android.apksigner.ApkSignerTool sign \
    // --append-signature --v4-single-signing-enabled true --v4-signing-enabled true --v3-signing-enabled false --v2-signing-enabled false --v1-signing-enabled false --stamp-timestamp-enabled false \
    // --ks NONE --ks-type HDIMAGE --ks-key-alias android_2013 --ks-pass pass:CryptoCert -key-pass pass:CryptoCert --ks-provider-name JCSPRSA --ks-provider-class ru.CryptoPro.JCSP.JCSPRSA --provider-class ru.CryptoPro.JCSP.JCSPRSA --provider-pos 1 \
    // app.apk

    // Verify all without v4 (GOST requires Java CSP):
    // java -Dkeytool.compat=true -Duse.cert.stub=true com.android.apksigner.ApkSignerTool verify \
    // --verbose --print-certs --provider-class ru.CryptoPro.JCSP.JCSP --provider-pos 1 \
    // app.apk

    // Verify all with v4 (GOST requires Java CSP):
    // java -Dkeytool.compat=true -Duse.cert.stub=true com.android.apksigner.ApkSignerTool verify \
    // --verbose --print-certs --provider-class ru.CryptoPro.JCSP.JCSP --provider-pos 1 \
    // --v4-signature-file app.apk.idsig \
    // app.apk

    // Additional information.
    // Add source timestamp v2 using --stamp-signer by RSA key android_2013:
    // java -Dkeytool.compat=true -Duse.cert.stub=true com.android.apksigner.ApkSignerTool sign \
    // --stamp-timestamp-enabled true --v4-signing-enabled false --v3-signing-enabled false --v2-signing-enabled false --v1-signing-enabled false \
    // --ks NONE --ks-type HDIMAGE --ks-key-alias android_2013 --ks-pass pass:CryptoCert -key-pass pass:CryptoCert --ks-provider-name JCSPRSA --ks-provider-class ru.CryptoPro.JCSP.JCSPRSA --provider-class ru.CryptoPro.JCSP.JCSPRSA --provider-pos 1 \
    // --stamp-signer \
    //      --ks NONE --ks-type HDIMAGE --ks-key-alias android_2013 --ks-pass pass:CryptoCert -key-pass pass:CryptoCert --ks-provider-name JCSPRSA --ks-provider-class ru.CryptoPro.JCSP.JCSPRSA --provider-class ru.CryptoPro.JCSP.JCSPRSA --provider-pos 1 \
    // app.apk

    @Rule
    public TemporaryFolder mTemporaryFolder = new TemporaryFolder();

    @BeforeClass
    public static void init() {
        Security.insertProviderAt(new JCSPRSA(), 1); // must be first to process private key and algorithms
        Security.addProvider(new JCSP());
    }

    @Test
    public void testVerifyApkAfter_V1_V2() throws Exception {
        List<ApkSigner.SignerConfig> signers = Collections.singletonList(getDefaultSignerGostConfig());
        File signedApk = sign(getDataSourceFromResources("gost-tests/original-v1-v2.apk"),
            new ApkSigner.Builder(signers)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false)
                    .setSourceStampTimestampEnabled(false)
                    .setOtherSignersSignaturesPreserved(true) // --append-signature
                    .setGostSigningEnabled(true) // --gost-signing-enabled
        );
        ApkVerifier.Result result = verify(signedApk, false);
        assertVerified(result);
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertTrue(result.isVerifiedUsingV2Scheme());
        assertGostVerified(result, signers.get(0).getCertificates().get(0));
        copy(signedApk, "original-v1-v2-gost.apk");
    }

    @Test
    public void testVerifyApkAfter_V1_V2_V3() throws Exception {
        List<ApkSigner.SignerConfig> signers = Collections.singletonList(getDefaultSignerGostConfig());
        File signedApk = sign(getDataSourceFromResources("gost-tests/original-v1-v2-v3.apk"),
            new ApkSigner.Builder(signers)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(false)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .setSourceStampTimestampEnabled(false)
                .setOtherSignersSignaturesPreserved(true) // --append-signature
                .setGostSigningEnabled(true) // --gost-signing-enabled
        );
        ApkVerifier.Result result = verify(signedApk, false);
        assertVerified(result);
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertTrue(result.isVerifiedUsingV2Scheme());
        assertTrue(result.isVerifiedUsingV3Scheme());
        assertGostVerified(result, signers.get(0).getCertificates().get(0));
        copy(signedApk, "original-v1-v2-v3-gost.apk");
    }

    @Test
    public void testVerifyApkAfter_V1_V2_V3_V4() throws Exception {
        List<ApkSigner.SignerConfig> gostSigners = Collections.singletonList(getDefaultSignerGostConfig());
        File signedApk = sign(getDataSourceFromResources("gost-tests/original-v1-v2-v3-v4.apk"),
            new ApkSigner.Builder(gostSigners)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(false)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .setSourceStampTimestampEnabled(false)
                .setOtherSignersSignaturesPreserved(true) // --append-signature
                .setGostSigningEnabled(true) // --gost-signing-enabled
        );
        // V4 is broken.
        ApkVerifier.Result result = verifyWithV4Signature(signedApk, "gost-tests/original-v1-v2-v3-v4.apk.idsig");
        assertVerified(result);
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertTrue(result.isVerifiedUsingV2Scheme());
        assertTrue(result.isVerifiedUsingV3Scheme());
        assertGostVerified(result, gostSigners.get(0).getCertificates().get(0));
        assertFalse(result.isVerifiedUsingV4Scheme());
        assertEquals(ApkVerifier.Issue.V4_SIG_DID_NOT_VERIFY, result.getV4SchemeSigners().get(0).getErrors().get(0).getIssue());
        // Sign v4 again.
        List<ApkSigner.SignerConfig> rsaSigners = Collections.singletonList(getDefaultSignerRsaConfig());
        signedApk = sign(signedApk,
            new ApkSigner.Builder(rsaSigners)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(false)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(true) // --v4-signing-enabled
                .setV4SingleSigningEnabled(true) // --v4-single-signing-enabled
                .setSourceStampTimestampEnabled(false)
                .setOtherSignersSignaturesPreserved(true) // --append-signature to preserve v1 jar entries
                .setGostSigningEnabled(false)
        );
        result = verify(signedApk, true);
        assertVerified(result);
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertTrue(result.isVerifiedUsingV2Scheme());
        assertTrue(result.isVerifiedUsingV3Scheme());
        assertGostVerified(result, gostSigners.get(0).getCertificates().get(0));
        assertTrue(result.isVerifiedUsingV4Scheme());
        copy(signedApk, "original-v1-v2-v3-gost-v4.apk");
    }

    @Test
    public void testVerifyApkAfter_V1_V2_SourceStampV2() throws Exception {
        List<ApkSigner.SignerConfig> signers = Collections.singletonList(getDefaultSignerGostConfig());
        File signedApk = sign(getDataSourceFromResources("gost-tests/original-v1-v2-timestampv2.apk"),
            new ApkSigner.Builder(signers)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(false)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .setSourceStampTimestampEnabled(false)
                .setOtherSignersSignaturesPreserved(true) // --append-signature
                .setGostSigningEnabled(true) // --gost-signing-enabled
        );
        ApkVerifier.Result result = verify(signedApk, false);
        assertVerified(result);
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertTrue(result.isVerifiedUsingV2Scheme());
        assertTrue(result.isSourceStampVerified());
        assertGostVerified(result, signers.get(0).getCertificates().get(0));
        copy(signedApk, "original-v1-v2-timestampv2-gost.apk");
    }

    @Test
    public void testVerifyApkAfter_V1_V2_V3_SourceStampV2() throws Exception {
        List<ApkSigner.SignerConfig> signers = Collections.singletonList(getDefaultSignerGostConfig());
        File signedApk = sign(getDataSourceFromResources("gost-tests/original-v1-v2-v3-timestampv2.apk"),
            new ApkSigner.Builder(signers)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(false)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .setSourceStampTimestampEnabled(false)
                .setOtherSignersSignaturesPreserved(true) // --append-signature
                .setGostSigningEnabled(true) // --gost-signing-enabled
        );
        ApkVerifier.Result result = verify(signedApk, false);
        assertVerified(result);
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertTrue(result.isVerifiedUsingV2Scheme());
        assertTrue(result.isVerifiedUsingV3Scheme());
        assertTrue(result.isSourceStampVerified());
        assertGostVerified(result, signers.get(0).getCertificates().get(0));
        copy(signedApk, "original-v1-v2-v3-timestampv2-gost.apk");
    }

    @Test
    public void testVerifyApkAfter_V1_V2_V3_V4_SourceStampV2() throws Exception {
        List<ApkSigner.SignerConfig> gostSigners = Collections.singletonList(getDefaultSignerGostConfig());
        File signedApk = sign(getDataSourceFromResources("gost-tests/original-v1-v2-v3-timestampv2-v4.apk"),
            new ApkSigner.Builder(gostSigners)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(false)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .setSourceStampTimestampEnabled(false)
                .setOtherSignersSignaturesPreserved(true) // --append-signature
                .setGostSigningEnabled(true) // --gost-signing-enabled
        );
        // V4 is broken.
        ApkVerifier.Result result = verifyWithV4Signature(signedApk, "gost-tests/original-v1-v2-v3-timestampv2-v4.apk.idsig");
        assertVerified(result);
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertTrue(result.isVerifiedUsingV2Scheme());
        assertTrue(result.isVerifiedUsingV3Scheme());
        assertTrue(result.isSourceStampVerified());
        assertGostVerified(result, gostSigners.get(0).getCertificates().get(0));
        assertFalse(result.isVerifiedUsingV4Scheme());
        assertEquals(ApkVerifier.Issue.V4_SIG_DID_NOT_VERIFY, result.getV4SchemeSigners().get(0).getErrors().get(0).getIssue());
        // Sign v4 again.
        List<ApkSigner.SignerConfig> rsaSigners = Collections.singletonList(getDefaultSignerRsaConfig());
        signedApk = sign(signedApk,
            new ApkSigner.Builder(rsaSigners)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(false)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(true) // --v4-signing-enabled
                .setV4SingleSigningEnabled(true) // --v4-single-signing-enabled
                .setSourceStampTimestampEnabled(false)
                .setOtherSignersSignaturesPreserved(true) // --append-signature to preserve v1 jar entries
                .setGostSigningEnabled(false)
        );
        result = verify(signedApk, true);
        assertVerified(result);
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertTrue(result.isVerifiedUsingV2Scheme());
        assertTrue(result.isVerifiedUsingV3Scheme());
        assertTrue(result.isSourceStampVerified());
        assertGostVerified(result, gostSigners.get(0).getCertificates().get(0));
        assertTrue(result.isVerifiedUsingV4Scheme());
        copy(signedApk, "original-v1-v2-v3-timestampv2-gost-v4.apk");
    }

    /*
    @Test
    public void testVerifyApkAfterRotate_V1_V2_V3() throws Exception {
        List<ApkSigner.SignerConfig> signers = Collections.singletonList(getDefaultSignerGostConfig());
        File signedApk = sign(getDataSourceFromResources("gost-tests/original-v1-v2-v3-rotate.apk"),
            new ApkSigner.Builder(signers)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(false)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .setSourceStampTimestampEnabled(false)
                .setOtherSignersSignaturesPreserved(true) // --append-signature
                .setGostSigningEnabled(true) // --gost-signing-enabled
        );
        ApkVerifier.Result result = verify(signedApk, false);
        assertVerified(result);
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertTrue(result.isVerifiedUsingV2Scheme());
        assertTrue(result.isVerifiedUsingV3Scheme());
        assertGostVerified(result, signers.get(0).getCertificates().get(0));
        copy(signedApk, "original-v1-v2-v3-rotate-then-gost.apk");
    }
    */

    @Test
    public void testVerifyUnalignedApkAfter_V1_V2() throws Exception {
        List<ApkSigner.SignerConfig> signers = Collections.singletonList(getDefaultSignerGostConfig());
        try {
            // Signing block will be aligned and previous signatures will be broken because of unaligned apk.
            sign(getDataSourceFromResources("gost-tests/app-debug-unaligned-v2.apk"),
                new ApkSigner.Builder(signers)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false)
                    .setSourceStampTimestampEnabled(false)
                    .setOtherSignersSignaturesPreserved(true) // --append-signature
                    .setGostSigningEnabled(true) // --gost-signing-enabled
            );
        } catch (IOException e) {
            assertEquals("Looks like apk is not aligned, padding 2768 byte(s) is required before Signing Block.", e.getMessage());
            return;
        }
        fail("Signing should fail.");
    }

    //------------------------------------------------------------------------------------------------------------------

    private ApkSigner.SignerConfig getDefaultSignerGostConfig()
        throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException,
        NoSuchAlgorithmException, NoSuchProviderException {
        return getDefaultSignerConfig("android_2013_gost", "JCSP");
    }

    private ApkSigner.SignerConfig getDefaultSignerRsaConfig()
            throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException,
            NoSuchAlgorithmException, NoSuchProviderException {
        return getDefaultSignerConfig("android_2013", "JCSPRSA");
    }

    private ApkSigner.SignerConfig getRotateSignerRsaConfig()
            throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException,
            NoSuchAlgorithmException, NoSuchProviderException {
        return getDefaultSignerConfig("android_2026_rotate", "JCSPRSA");
    }

    private ApkSigner.SignerConfig getDefaultSignerConfig(String alias, String provider)
        throws KeyStoreException, NoSuchProviderException, IOException, CertificateException,
        NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("PFXSTORE", provider);
        keyStore.load(Resources.toInputStream(getClass(), "gost-tests/" + alias + ".pfx"), "CryptoCert".toCharArray());
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        List<X509Certificate> certificates = Arrays.stream(keyStore.getCertificateChain(alias)).map(x -> (X509Certificate)x).collect(Collectors.toList());
        ApkSigner.SignerConfig.Builder signerConfigBuilder = new ApkSigner.SignerConfig.Builder(alias, new KeyConfig.Jca(privateKey), certificates);
        return signerConfigBuilder.build();
    }

    private DataSource getDataSourceFromResources(String inResourceName)
        throws Exception {
        byte[] apkBytes = Resources.toByteArray(getClass(), inResourceName);
        return DataSources.asDataSource(ByteBuffer.wrap(apkBytes));
    }

    private File sign(DataSource in, ApkSigner.Builder apkSignerBuilder)
        throws IOException, ApkFormatException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        File outFile = mTemporaryFolder.newFile();
        apkSignerBuilder.setInputApk(in).setOutputApk(outFile);
        File outFileIdSig = new File(outFile.getCanonicalPath() + ".idsig");
        apkSignerBuilder.setV4SignatureOutputFile(outFileIdSig);
        apkSignerBuilder.setV4ErrorReportingEnabled(true);
        apkSignerBuilder.build().sign();
        return outFile;
    }

    private File sign(File in, ApkSigner.Builder apkSignerBuilder)
        throws IOException, ApkFormatException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        File outFile = mTemporaryFolder.newFile();
        apkSignerBuilder.setInputApk(in).setOutputApk(outFile);
        File outFileIdSig = new File(outFile.getCanonicalPath() + ".idsig");
        apkSignerBuilder.setV4SignatureOutputFile(outFileIdSig);
        apkSignerBuilder.setV4ErrorReportingEnabled(true);
        apkSignerBuilder.build().sign();
        return outFile;
    }

    private ApkVerifier.Result verify(DataSource in)
        throws IOException, ApkFormatException, NoSuchAlgorithmException {
        ApkVerifier.Builder builder = new ApkVerifier.Builder(in);
        return builder.build().verify();
    }

    private ApkVerifier.Result verify(File apk, boolean v4)
        throws IOException, ApkFormatException, NoSuchAlgorithmException {
        ApkVerifier.Builder builder = new ApkVerifier.Builder(apk);
        File idSig = new File(apk.getCanonicalPath() + ".idsig");
        if (idSig.exists()) {
            builder.setV4SignatureFile(idSig);
        }
        else {
            assertFalse("File " + idSig.getAbsolutePath() + " is required.", v4);
        }
        return builder.build().verify();
    }

    private ApkVerifier.Result verifyWithV4Signature(
            File apk, String v4SignatureFile)
            throws IOException, ApkFormatException, NoSuchAlgorithmException {
        ApkVerifier.Builder builder = new ApkVerifier.Builder(apk);
        builder.setV4SignatureFile(Resources.toFile(getClass(), v4SignatureFile, mTemporaryFolder));
        return builder.build().verify();
    }

    static void assertVerified(ApkVerifier.Result result) {
        assertVerified(result, "APK");
    }

    static void assertGostVerified(ApkVerifier.Result result, X509Certificate expectedSignerCertificate) {
        assertTrue(result.isVerifiedUsingGostScheme());
        assertFalse(result.getGostSchemeSigners().isEmpty());
        assertEquals(result.getGostSchemeSigners().get(0).getCertificate(), expectedSignerCertificate);
    }

    static void assertVerified(ApkVerifier.Result result, String apkId) {
        if (result.isVerified()) {
            return;
        }
        StringBuilder msg = new StringBuilder();
        for (ApkVerifier.IssueWithParams issue : result.getErrors()) {
            if (msg.length() > 0) {
                msg.append('\n');
            }
            msg.append(issue);
        }
        for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeSigners()) {
            String signerName = signer.getName();
            for (ApkVerifier.IssueWithParams issue : signer.getErrors()) {
                if (msg.length() > 0) {
                    msg.append('\n');
                }
                msg.append("JAR signer ")
                        .append(signerName)
                        .append(": ")
                        .append(issue.getIssue())
                        .append(": ")
                        .append(issue);
            }
        }
        for (ApkVerifier.Result.V2SchemeSignerInfo signer : result.getV2SchemeSigners()) {
            String signerName = "signer #" + (signer.getIndex() + 1);
            for (ApkVerifier.IssueWithParams issue : signer.getErrors()) {
                if (msg.length() > 0) {
                    msg.append('\n');
                }
                msg.append("APK Signature Scheme v2 signer ")
                        .append(signerName)
                        .append(": ")
                        .append(issue.getIssue())
                        .append(": ")
                        .append(issue);
            }
        }
        for (ApkVerifier.Result.GostSchemeSignerInfo signer : result.getGostSchemeSigners()) {
            String signerName = "signer #" + (signer.getIndex() + 1);
            for (ApkVerifier.IssueWithParams issue : signer.getErrors()) {
                if (msg.length() > 0) {
                    msg.append('\n');
                }
                msg.append("APK Gost Signature Scheme signer ")
                        .append(signerName)
                        .append(": ")
                        .append(issue.getIssue())
                        .append(": ")
                        .append(issue);
            }
        }
        for (ApkVerifier.Result.V3SchemeSignerInfo signer : result.getV3SchemeSigners()) {
            String signerName = "signer #" + (signer.getIndex() + 1);
            for (ApkVerifier.IssueWithParams issue : signer.getErrors()) {
                if (msg.length() > 0) {
                    msg.append('\n');
                }
                msg.append("APK Signature Scheme v3 signer ")
                        .append(signerName)
                        .append(": ")
                        .append(issue.getIssue())
                        .append(": ")
                        .append(issue);
            }
        }
        for (ApkVerifier.Result.V3SchemeSignerInfo signer : result.getV31SchemeSigners()) {
            String signerName = "signer #" + (signer.getIndex() + 1);
            for (ApkVerifier.IssueWithParams issue : signer.getErrors()) {
                if (msg.length() > 0) {
                    msg.append('\n');
                }
                msg.append("APK Signature Scheme v3.1 signer ")
                        .append(signerName)
                        .append(": ")
                        .append(issue.getIssue())
                        .append(": ")
                        .append(issue);
            }
        }
        fail(apkId + " did not verify: " + msg);
    }

    private void copy(File in, String name) throws IOException {
        if (false) {
            File saved = new File(System.getProperty("user.dir"), "saved");
            saved.mkdirs();
            Files.copy(in, new File(saved, name));
        }
    }

}
