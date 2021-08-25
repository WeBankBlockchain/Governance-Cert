/*
 * Copyright 2014-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
import org.bouncycastle.asn1.x509.KeyUsage;
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
                .commonName("dir_chain_ca")
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

        // TODO: 2021/8/21 X509v3 Subject Key Identifier:  X509v3 Authority Key Identifier
        X500NameInfo info = X500NameInfo.builder()
                .commonName("dir_chain_ca")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();

        CryptoKeyPair cryptoKeyPair = SM2KeyHandler.generateSM2KeyPair();
        KeyPair keyPair = cryptoKeyPair.getKeyPair();
        String encryptPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()),
                EccTypeEnums.SM2P256V1);

        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);

        X509Certificate certificate = certService.createRootCertificate(SIGNATURE_SM2, info, keyUsage, beginDate, endDate, keyPair.getPublic(), keyPair.getPrivate());
        certificate.verify(keyPair.getPublic());
        new File("out").mkdirs();
        FileUtil.writeUtf8String(encryptPrivateKey, FileUtil.newFile("out/gmca.key"));
        CertUtils.writeCrt(certificate, "out/gmca.crt");
    }

    @Test
    public void testCreateCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("agencyA")
                .organizationalUnitName("fisco-bcos")
                .organizationName("agency")
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
        String encryptPrivateKey = FileUtil.readUtf8String(FileUtil.newFile("out/gmca.key"));
        PrivateKey privateKey = PemEncrypt.getPrivateKey(encryptPrivateKey);

        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);

        X509Certificate childCert = certService.createChildCertificate(true, SIGNATURE_SM2, parentCert,
                request, keyUsage, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/gmagencyA.crt");
    }

    @Test
    public void testCreateNodeCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("gm")
                .organizationalUnitName("fisco-bcos")
                .organizationName("node")
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
        String pemPrivateKey = FileUtil.readUtf8String(FileUtil.newFile("out/gmagencyA.key"));
        PrivateKey privateKey = PemEncrypt.getPrivateKey(pemPrivateKey);

        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation);

        X509Certificate childCert = certService.createChildCertificate(false, SIGNATURE_SM2, parentCert,
                request, keyUsage, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/gmnode.crt");
    }

    @Test
    public void testAppendAgencyCrt2Node() throws Exception {
        String agencyStr = FileUtil.readUtf8String(FileUtil.newFile("out/gmagencyA.crt"));
        FileUtil.appendUtf8String(agencyStr, FileUtil.newFile("out/gmnode.crt"));
    }

    @Test
    public void testCopyNodeSdk() throws Exception {
        String nodeStr = FileUtil.readUtf8String(FileUtil.newFile("out/gmnode.crt"));
        FileUtil.writeUtf8String(nodeStr, FileUtil.newFile("out/gmsdk.crt"));
        String keyStr = FileUtil.readUtf8String(FileUtil.newFile("out/gmnode.key"));
        FileUtil.writeUtf8String(keyStr, FileUtil.newFile("out/gmsdk.key"));
    }

    @Test
    public void testCreateEnNodeCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("gm")
                .organizationalUnitName("fisco-bcos")
                .organizationName("ennode")
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
        String pemPrivateKey = FileUtil.readUtf8String(FileUtil.newFile("out/gmagencyA.key"));
        PrivateKey privateKey = PemEncrypt.getPrivateKey(pemPrivateKey);

        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement);

        X509Certificate childCert = certService.createChildCertificate(false, SIGNATURE_SM2, parentCert,
                request, keyUsage, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/gmennode.crt");
    }


    @Test
    public void testCopyEnNodeSdk() throws Exception {
        String nodeStr = FileUtil.readUtf8String(FileUtil.newFile("out/gmennode.crt"));
        FileUtil.writeUtf8String(nodeStr, FileUtil.newFile("out/gmensdk.crt"));
        String keyStr = FileUtil.readUtf8String(FileUtil.newFile("out/gmennode.key"));
        FileUtil.writeUtf8String(keyStr, FileUtil.newFile("out/gmensdk.key"));
    }


    @Test
    public void testGetNodeId() throws Exception {
        X509Certificate gmNodeCert = CertUtils.readCrt("out/gmnode.crt");
        PublicKey publicKey = gmNodeCert.getPublicKey();
        String gmNodeId = HexUtil.encodeHexStr(publicKey.getEncoded());
        FileUtil.writeUtf8String(StrUtil.subByCodePoint(gmNodeId, 54, gmNodeId.length()), FileUtil.newFile("out/gmnode.nodeid"));

    }


}
