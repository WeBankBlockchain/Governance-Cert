package com.webank.cert.toolkit;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import com.webank.cert.toolkit.encrypt.PemEncrypt;
import com.webank.cert.toolkit.enums.EccTypeEnums;
import com.webank.cert.toolkit.handler.SM2KeyHandler;
import com.webank.cert.toolkit.model.X500NameInfo;
import com.webank.cert.toolkit.service.CertService;
import com.webank.cert.toolkit.utils.CertUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.fisco.bcos.sdk.crypto.keypair.SM2KeyPair;
import org.fisco.bcos.sdk.crypto.keystore.KeyTool;
import org.junit.Test;
import org.web3j.utils.Numeric;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertServiceGMTest extends BaseTest {


    private CertService certService = new CertService();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static final String SIGNATURE_SM2 = "SM3WITHSM2";

    private String caKey = "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKlhdkyDVEyXTNKwB\n" +
            "LxG0DIY1LRkvIl0OVIYxMpirSwGhRANCAATbwLNhEtyBheIYfZc/2NWXNLzDiNZI\n" +
            "S6ZEqJnLJcQvUBjfMqDla3hqnCDGLODgqUV81b+m1E0JzF9tEap+RwWb\n" +
            "-----END PRIVATE KEY-----\n";


    @Test
    public void testCreateRootCertificateByKey() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("chain")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();

        byte[] bytes = PemEncrypt.decryptPrivateKey(caKey);
        KeyPair keyPair = SM2KeyHandler.generateSM2KeyPair(Numeric.toHexStringNoPrefix(bytes)).getKeyPair();

        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);
        X509Certificate certificate = certService.createRootCertificate(SIGNATURE_SM2, info,
                null, beginDate, endDate, keyPair.getPublic(), keyPair.getPrivate());
        certificate.verify(keyPair.getPublic());
        new File("out").mkdirs();
        FileUtil.writeUtf8String(caKey, FileUtil.newFile("out/gmca1.key"));
        CertUtils.writeCrt(certificate, "out/gmca1.crt");
    }

    @Test
    public void testCreateRootCertificate() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("chain")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();

        CryptoKeyPair cryptoKeyPair = SM2KeyHandler.generateSM2KeyPair();
        KeyPair keyPair = cryptoKeyPair.getKeyPair();
        String encryptPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()),
                EccTypeEnums.SM2P256V1);

        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);
        X509Certificate certificate = certService.createRootCertificate(SIGNATURE_SM2, info, null, beginDate, endDate, keyPair.getPublic(), keyPair.getPrivate());
        certificate.verify(keyPair.getPublic());
        new File("out").mkdirs();
        FileUtil.writeUtf8String(encryptPrivateKey, FileUtil.newFile("out/gmca.key"));
        CertUtils.writeCrt(certificate, "out/gmca.crt");
    }

    @Test
    public void testCreateCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("agencyA")
                .organizationalUnitName("agencyA")
                .organizationName("fisco-bcos")
                .build();

        CryptoKeyPair cryptoKeyPair = SM2KeyHandler.generateSM2KeyPair();
        KeyPair keyPair = cryptoKeyPair.getKeyPair();
        String encryptPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()), EccTypeEnums.SM2P256V1);

        PKCS10CertificationRequest request = certService.createCertRequest(info, keyPair.getPublic(), keyPair.getPrivate(), SIGNATURE_SM2);
        FileUtil.writeUtf8String(encryptPrivateKey, FileUtil.newFile("out/gmagencyA.key"));
        CertUtils.writeCsr(request, "out/gmagencyA.csr");
    }

    @Test
    public void testCreateChildCertificate() throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);

        PKCS10CertificationRequest request = CertUtils.readCsr("out/gmagencyA.csr");
        X509Certificate parentCert = CertUtils.readCrt("out/gmca.crt");
        String encryptPrivateKey = FileUtil.readString(FileUtil.newFile("out/gmca.key"), CharsetUtil.CHARSET_UTF_8);
        PrivateKey privateKey = PemEncrypt.getPrivateKey(encryptPrivateKey);

        X509Certificate childCert = certService.createChildCertificate(true, SIGNATURE_SM2, parentCert,
                request, null, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/gmagencyA.crt");
    }

    @Test
    public void testCreateNodeCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("nodeA")
                .organizationalUnitName("agencyA")
                .organizationName("fisco-bcos")
                .build();

        CryptoKeyPair cryptoKeyPair = SM2KeyHandler.generateSM2KeyPair();
        KeyPair keyPair = cryptoKeyPair.getKeyPair();
        String pemPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()), EccTypeEnums.SM2P256V1);

        PKCS10CertificationRequest request = certService.createCertRequest(info, keyPair.getPublic(), keyPair.getPrivate(), SIGNATURE_SM2);
        FileUtil.writeUtf8String(pemPrivateKey, FileUtil.newFile("out/gmnode.key"));
        CertUtils.writeCsr(request, "out/gmnode.csr");
    }

    @Test
    public void testCreateAgencyChildCertificate() throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);

        PKCS10CertificationRequest request = CertUtils.readCsr("out/gmnode.csr");
        X509Certificate parentCert = CertUtils.readCrt("out/gmagencyA.crt");
        String pemPrivateKey = FileUtil.readString(FileUtil.newFile("out/gmagencyA.key"), CharsetUtil.CHARSET_UTF_8);
        PrivateKey privateKey = PemEncrypt.getPrivateKey(pemPrivateKey);

        X509Certificate childCert = certService.createChildCertificate(true, SIGNATURE_SM2, parentCert,
                request, null, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/gmnode.crt");
    }

    @Test
    public void testCreateEnNodeCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("nodeA")
                .organizationalUnitName("agencyA")
                .organizationName("fisco-bcos")
                .build();

        CryptoKeyPair cryptoKeyPair = SM2KeyHandler.generateSM2KeyPair();
        KeyPair keyPair = cryptoKeyPair.getKeyPair();
        String pemPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()), EccTypeEnums.SM2P256V1);

        PKCS10CertificationRequest request = certService.createCertRequest(info, keyPair.getPublic(), keyPair.getPrivate(), SIGNATURE_SM2);
        FileUtil.writeUtf8String(pemPrivateKey, FileUtil.newFile("out/gmennode.key"));
        CertUtils.writeCsr(request, "out/gmennode.csr");
    }

    @Test
    public void testCreateAgencyChildEnCertificate() throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);

        PKCS10CertificationRequest request = CertUtils.readCsr("out/gmennode.csr");
        X509Certificate parentCert = CertUtils.readCrt("out/gmagencyA.crt");
        String pemPrivateKey = FileUtil.readString(FileUtil.newFile("out/gmagencyA.key"), CharsetUtil.CHARSET_UTF_8);
        PrivateKey privateKey = PemEncrypt.getPrivateKey(pemPrivateKey);

        X509Certificate childCert = certService.createChildCertificate(true, SIGNATURE_SM2, parentCert,
                request, null, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/gmennode.crt");
    }


    @Test
    public void testCreateSdkNodeCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("gmsdk")
                .organizationalUnitName("agencyA")
                .organizationName("fisco-bcos")
                .build();

        CryptoKeyPair cryptoKeyPair = SM2KeyHandler.generateSM2KeyPair();
        KeyPair keyPair = cryptoKeyPair.getKeyPair();
        String pemPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()), EccTypeEnums.SM2P256V1);

        PKCS10CertificationRequest request = certService.createCertRequest(info, keyPair.getPublic(), keyPair.getPrivate(), SIGNATURE_SM2);
        FileUtil.writeUtf8String(pemPrivateKey, FileUtil.newFile("out/gmsdk.key"));
        CertUtils.writeCsr(request, "out/gmsdk.csr");
    }

    @Test
    public void testCreateAgencyChildSdkCertificate() throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);

        PKCS10CertificationRequest request = CertUtils.readCsr("out/gmsdk.csr");
        X509Certificate parentCert = CertUtils.readCrt("out/gmagencyA.crt");
        String pemPrivateKey = FileUtil.readString(FileUtil.newFile("out/gmagencyA.key"), CharsetUtil.CHARSET_UTF_8);
        PrivateKey privateKey = PemEncrypt.getPrivateKey(pemPrivateKey);

        X509Certificate childCert = certService.createChildCertificate(true, SIGNATURE_SM2, parentCert,
                request, null, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/gmsdk.crt");
    }

    @Test
    public void testCreateEnSdkNodeCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("gmensdk")
                .organizationalUnitName("agencyA")
                .organizationName("fisco-bcos")
                .build();

        CryptoKeyPair cryptoKeyPair = SM2KeyHandler.generateSM2KeyPair();
        KeyPair keyPair = cryptoKeyPair.getKeyPair();
        String pemPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()), EccTypeEnums.SM2P256V1);

        PKCS10CertificationRequest request = certService.createCertRequest(info, keyPair.getPublic(), keyPair.getPrivate(), SIGNATURE_SM2);
        FileUtil.writeUtf8String(pemPrivateKey, FileUtil.newFile("out/gmensdk.key"));
        CertUtils.writeCsr(request, "out/gmensdk.csr");
    }

    @Test
    public void testCreateAgencyChildEnSdkCertificate() throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);

        PKCS10CertificationRequest request = CertUtils.readCsr("out/gmensdk.csr");
        X509Certificate parentCert = CertUtils.readCrt("out/gmagencyA.crt");
        String pemPrivateKey = FileUtil.readString(FileUtil.newFile("out/gmagencyA.key"), CharsetUtil.CHARSET_UTF_8);
        PrivateKey privateKey = PemEncrypt.getPrivateKey(pemPrivateKey);

        X509Certificate childCert = certService.createChildCertificate(true, SIGNATURE_SM2, parentCert,
                request, null, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/gmensdk.crt");
    }


    @Test
    public void testGetNodeId() throws Exception {
        X509Certificate gmNodeCert = CertUtils.readCrt("out/gmnode.crt");
        PublicKey publicKey = gmNodeCert.getPublicKey();
        String gmNodeId = HexUtil.encodeHexStr(publicKey.getEncoded());
        FileUtil.writeUtf8String(StrUtil.subByCodePoint(gmNodeId, 54, gmNodeId.length()), FileUtil.newFile("out/gmnode.nodeid"));

    }


}
