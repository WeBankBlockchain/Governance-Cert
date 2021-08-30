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
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import com.webank.cert.toolkit.encrypt.PemEncrypt;
import com.webank.cert.toolkit.enums.EccTypeEnums;
import com.webank.cert.toolkit.handler.ECKeyHandler;
import com.webank.cert.toolkit.model.X500NameInfo;
import com.webank.cert.toolkit.service.CertService;
import com.webank.cert.toolkit.utils.CertUtils;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.junit.Test;
import org.web3j.utils.Numeric;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertServiceSMTest extends BaseTest {


    private CertService certService = new CertService();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static final String SIGNATURE_ECDSA = "SHA256WITHECDSA";

    private String caKey = "-----BEGIN PRIVATE KEY-----\r\n" +
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgVwYLwSBixBvIOzMK3nxu\r\n" +
            "RwEHYQA3JcgCScKVnGiEna2hRANCAAT8E0MbSnBzrZJoeNuZauXY2iZOe8Pxlmsl\r\n" +
            "1pwCkC7YkBvur8EDlD1nZOEGwoqjpwMmfDzfL9fK8LQFqdzKMTg1\r\n" +
            "-----END PRIVATE KEY-----\r\n";


    @Test
    public void testCreateRootCertificateByKey() throws Exception {

        X500NameInfo info = X500NameInfo.builder()
                .commonName("dir_chain_ca")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();

        byte[] bytes = PemEncrypt.decryptPrivateKey(caKey);
        KeyPair keyPair = ECKeyHandler.generateECKeyPair(Numeric.toHexStringNoPrefix(bytes)).getKeyPair();

        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);
        X509Certificate certificate = certService.createRootCertificate(SIGNATURE_ECDSA, info,
                null, beginDate, endDate, keyPair.getPublic(), keyPair.getPrivate());
        certificate.verify(keyPair.getPublic());
        new File("out/sm").mkdirs();
        FileUtil.writeUtf8String(caKey, FileUtil.newFile("out/sm/ca1.key"));
        CertUtils.writeCrt(certificate, "out/sm/ca1.crt");
    }

    @Test
    public void testCreateRootCertificate() throws Exception {

        X500NameInfo info = X500NameInfo.builder()
                .commonName("dir_chain_ca")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();

        CryptoKeyPair cryptoKeyPair = ECKeyHandler.generateECKeyPair();
        KeyPair keyPair = cryptoKeyPair.getKeyPair();
        String encryptPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()), EccTypeEnums.SECP256K1);

        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);
//        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);

        X509Certificate certificate = certService.createRootCertificate(SIGNATURE_ECDSA, info, null, beginDate, endDate, keyPair.getPublic(), keyPair.getPrivate());
        certificate.verify(keyPair.getPublic());
        new File("out/sm").mkdirs();
        FileUtil.writeUtf8String(encryptPrivateKey, FileUtil.newFile("out/sm/ca.key"));
        CertUtils.writeCrt(certificate, "out/sm/ca.crt");
    }

    @Test
    public void testCreateCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("agencyA")
                .organizationalUnitName("fisco-bcos")
                .organizationName("agency")
                .build();

        CryptoKeyPair cryptoKeyPair = ECKeyHandler.generateECKeyPair();
        KeyPair keyPair = cryptoKeyPair.getKeyPair();
        String encryptPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()), EccTypeEnums.SECP256K1);

        PKCS10CertificationRequest request = certService.createCertRequest(info, keyPair.getPublic(), keyPair.getPrivate(), SIGNATURE_ECDSA);
        FileUtil.writeUtf8String(encryptPrivateKey, FileUtil.newFile("out/sm/agencyA.key"));
        CertUtils.writeCsr(request, "out/sm/agencyA.csr");
    }

    @Test
    public void testCreateChildCertificate() throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);

        PKCS10CertificationRequest request = CertUtils.readCsr("out/sm/agencyA.csr");
        X509Certificate parentCert = CertUtils.readCrt("out/sm/ca.crt");
        String encryptPrivateKey = FileUtil.readUtf8String(FileUtil.newFile("out/sm/ca.key"));
        PrivateKey privateKey = PemEncrypt.getPrivateKey(encryptPrivateKey);

//        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);

        X509Certificate childCert = certService.createChildCertificate(true, SIGNATURE_ECDSA, parentCert,
                request, null, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/sm/agencyA.crt");
    }

    @Test
    public void testCreateNodeCertRequest() throws Exception {
        X500NameInfo info = X500NameInfo.builder()
                .commonName("gm")
                .organizationalUnitName("fisco-bcos")
                .organizationName("node")
                .build();

        CryptoKeyPair cryptoKeyPair = ECKeyHandler.generateECKeyPair();
        KeyPair keyPair = cryptoKeyPair.getKeyPair();
        String pemPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()), EccTypeEnums.SECP256K1);

        PKCS10CertificationRequest request = certService.createCertRequest(info, keyPair.getPublic(), keyPair.getPrivate(), SIGNATURE_ECDSA);
        FileUtil.writeUtf8String(pemPrivateKey, FileUtil.newFile("out/sm/node.key"));
        CertUtils.writeCsr(request, "out/sm/node.csr");

    }

    @Test
    public void testCreateAgencyChildCertificate() throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);

        PKCS10CertificationRequest request = CertUtils.readCsr("out/sm/node.csr");
        X509Certificate parentCert = CertUtils.readCrt("out/sm/agencyA.crt");
        String pemPrivateKey = FileUtil.readUtf8String(FileUtil.newFile("out/sm/agencyA.key"));
        PrivateKey privateKey = PemEncrypt.getPrivateKey(pemPrivateKey);

        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment);

        X509Certificate childCert = certService.createChildCertificate(false, SIGNATURE_ECDSA, parentCert,
                request, keyUsage, beginDate, endDate, privateKey);
        childCert.verify(parentCert.getPublicKey());
        CertUtils.writeCrt(childCert, "out/sm/node.crt");
    }

    @Test
    public void testAppendAgencyCrt2Node() {
        String agencyStr = FileUtil.readUtf8String(FileUtil.newFile("out/sm/agencyA.crt"));
        FileUtil.appendUtf8String(agencyStr, FileUtil.newFile("out/sm/node.crt"));
    }

    @Test
    public void testCopyNodeSdk() {
        String nodeStr = FileUtil.readUtf8String(FileUtil.newFile("out/sm/node.crt"));
        FileUtil.writeUtf8String(nodeStr, FileUtil.newFile("out/sm/sdk.crt"));
        String keyStr = FileUtil.readUtf8String(FileUtil.newFile("out/sm/node.key"));
        FileUtil.writeUtf8String(keyStr, FileUtil.newFile("out/sm/sdk.key"));
    }

    @Test
    public void testGetNodeId() throws Exception {
        X509Certificate gmNodeCert = CertUtils.readCrt("out/sm/node.crt");
        PublicKey publicKey = gmNodeCert.getPublicKey();
        String gmNodeId = HexUtil.encodeHexStr(publicKey.getEncoded());
        FileUtil.writeUtf8String(StrUtil.subByCodePoint(gmNodeId, 48, gmNodeId.length()), FileUtil.newFile("out/sm/node.nodeid"));

    }


}
