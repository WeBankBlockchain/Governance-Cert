package com.webank.cert.toolkit;

import com.webank.cert.toolkit.model.X500NameInfo;
import com.webank.cert.toolkit.service.CertService;
import com.webank.cert.toolkit.utils.CertUtils;
import com.webank.cert.toolkit.utils.KeyUtils;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;

import java.io.File;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

public class CertServiceECDSATest extends BaseTest {


    private CertService certService = new CertService();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static final String SIGNATURE_ALGORITHM = "SHA256WITHECDSA";

    private String caKey = "-----BEGIN EC PRIVATE KEY-----\n" +
            "MHQCAQEEIJyqF2CBZ5IrLO3Dn7V1qSKHSrvfJqFV4Yz4seIf/TnMoAcGBSuBBAAK\n" +
            "oUQDQgAEEGXORMillAez9kHaCq+Wq73TCZUGY0kJP5EvEkpRuwZ7Ws5RJmRxdoxc\n" +
            "eR6q1Lzw/g5/IrrjSO6RGhOZiVxy8Q==\n" +
            "-----END EC PRIVATE KEY-----";


   /* @Test
    public void testCreateRootCertificateByKey() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("chain")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();

        KeyPair keyPair = KeyUtils.getECKeyPair(caKey);

        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);
        X509Certificate certificate = certService.createRootCertificate(SIGNATURE_ALGORITHM, info,
                null, beginDate, endDate, publicKey, privateKey);
        certificate.verify(publicKey);
        new File("out").mkdirs();
        CertUtils.writeKey(privateKey, "out/ca.key");
        CertUtils.writeCrt(certificate, "out/ca.crt");
    }*/

    @Test
    public void testCreateRootCertificate() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("chain")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();

        KeyPair keyPair = KeyUtils.generateECDSAKeyPair();

        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);
        X509Certificate certificate = certService.createRootCertificate(SIGNATURE_ALGORITHM, info,
                null, beginDate, endDate, publicKey, privateKey);
        certificate.verify(publicKey);
        new File("out").mkdirs();
        CertUtils.writeKey(privateKey, "out/ca.key");
        CertUtils.writeCrt(certificate, "out/ca.crt");
    }




    @Test
    public void testCreateCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("agencyA")
                .organizationalUnitName("agencyA")
                .organizationName("fisco-bcos")
                .build();

        KeyPair keyPair = KeyUtils.generateECDSAKeyPair();

        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();

        CertUtils.writeKey(privateKey, "out/agencyA.key");
        PKCS10CertificationRequest request = certService.createCertRequest(info, publicKey, privateKey,
                SIGNATURE_ALGORITHM);
        CertUtils.writeCsr(request, "out/agencyA.csr");
        CertUtils.readCsr("out/agencyA.csr");
    }


    @Test
    public void testCreateChildCertificate() throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);

        PKCS10CertificationRequest request = CertUtils.readCsr("out/agencyA.csr");
        X509Certificate parentCert = CertUtils.readCrt("out/ca.crt");
        PEMKeyPair pemKeyPair = CertUtils.readKey("out/ca.key");

        PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(
                new PKCS8EncodedKeySpec(pemKeyPair.getPrivateKeyInfo().getEncoded()));


        X509Certificate childCert = certService.createChildCertificate(true, SIGNATURE_ALGORITHM, parentCert,
                request, null, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/agencyA.crt");
    }

    @Test
    public void testCreateNodeCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("nodeA")
                .organizationalUnitName("agencyA")
                .organizationName("fisco-bcos")
                .build();

        KeyPair keyPair = KeyUtils.generateECDSAKeyPair();

        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();

        CertUtils.writeKey(privateKey, "out/nodeA.key");
        PKCS10CertificationRequest request = certService.createCertRequest(info, publicKey, privateKey,
                SIGNATURE_ALGORITHM);
        CertUtils.writeCsr(request, "out/nodeA.csr");
        CertUtils.readCsr("out/nodeA.csr");
    }


    @Test
    public void testCreateAgencyChildCertificate() throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);

        PKCS10CertificationRequest request = CertUtils.readCsr("out/nodeA.csr");
        X509Certificate parentCert = CertUtils.readCrt("out/agencyA.crt");
        PEMKeyPair pemKeyPair = CertUtils.readKey("out/agencyA.key");

        PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(
                new PKCS8EncodedKeySpec(pemKeyPair.getPrivateKeyInfo().getEncoded()));


        X509Certificate childCert = certService.createChildCertificate(true, SIGNATURE_ALGORITHM, parentCert,
                request, null, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/nodeA.crt");
        CertUtils.writeCrt(childCert, "out/nodeA.pub");
    }
}
