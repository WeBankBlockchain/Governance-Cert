//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.webank.cert.mgr.service;

import com.webank.cert.mgr.db.cert.entity.CertInfo;
import com.webank.cert.mgr.db.cert.entity.CertKeyInfo;
import com.webank.cert.mgr.db.cert.entity.CertRequestInfo;
import com.webank.cert.mgr.enums.KeyAlgorithmEnums;
import com.webank.cert.mgr.enums.MgrExceptionCodeEnums;
import com.webank.cert.mgr.exception.CertMgrException;
import com.webank.cert.mgr.handler.CertHandler;
import com.webank.cert.mgr.model.vo.CertKeyVO;
import com.webank.cert.mgr.model.vo.CertRequestVO;
import com.webank.cert.mgr.model.vo.CertVO;
import com.webank.cert.mgr.utils.TransformUtils;
import com.webank.cert.toolkit.model.X500NameInfo;
import com.webank.cert.toolkit.utils.CertUtils;
import com.webank.cert.toolkit.utils.KeyUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.web3j.crypto.ECKeyPair;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.List;

@Service
public class CertManagerService {
    @Autowired
    private CertHandler certHandler;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public CertManagerService() {
    }

    public CertVO createRootCert(String userId, X500NameInfo issuer) throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 315360000000L);
        return this.createRootCert(userId, issuer, beginDate, endDate);
    }

    public CertVO createRootCert(String userId, X500NameInfo issuer, Date beginDate, Date endDate) throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair();
        String pemPrivateKey = CertUtils.readPEMAsString(keyPair.getPrivate());
        long certKeyId = this.importPrivateKey(userId, pemPrivateKey, KeyAlgorithmEnums.RSA.getKeyAlgorithm());
        return this.createRootCert(userId, certKeyId, issuer, beginDate, endDate);
    }

    public CertVO createRootCert(String userId, long certKeyId, X500NameInfo issuer, Date beginDate, Date endDate) throws Exception {
        return this.createRootCert(userId, certKeyId, issuer, (KeyUsage)null, beginDate, endDate);
    }

    public CertVO createRootCert(String userId, long certKeyId, X500NameInfo issuer, KeyUsage keyUsage, Date beginDate, Date endDate) throws Exception {
        CertInfo certInfo = this.certHandler.createRootCert(userId, certKeyId, (String)null, (KeyAlgorithmEnums)null, issuer, keyUsage, beginDate, endDate);
        return (CertVO) TransformUtils.simpleTransform(certInfo, CertVO.class);
    }

    public CertVO createRootCertByHexPriKey(String userId, String hexPrivateKey, KeyAlgorithmEnums keyAlgorithm, X500NameInfo issuer) throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 315360000000L);
        return this.createRootCertByHexPriKey(userId, hexPrivateKey, keyAlgorithm, issuer, beginDate, endDate);
    }

    public CertVO createRootCertByHexPriKey(String userId, String hexPrivateKey, KeyAlgorithmEnums keyAlgorithm, X500NameInfo issuer, Date beginDate, Date endDate) throws Exception {
        String pemPrivateKey = this.getPemPrivateKey(hexPrivateKey, keyAlgorithm);
        return this.createRootCert(userId, pemPrivateKey, keyAlgorithm, issuer, beginDate, endDate);
    }

    public CertVO createRootCert(String userId, String pemPrivateKey, KeyAlgorithmEnums keyAlgorithm, X500NameInfo issuer) throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 315360000000L);
        return this.createRootCert(userId, pemPrivateKey, keyAlgorithm, issuer, beginDate, endDate);
    }

    public CertVO createRootCert(String userId, String pemPrivateKey, KeyAlgorithmEnums keyAlgorithm, X500NameInfo issuer, Date beginDate, Date endDate) throws Exception {
        return this.createRootCert(userId, pemPrivateKey, keyAlgorithm, issuer, (KeyUsage)null, beginDate, endDate);
    }

    public CertVO createRootCert(String userId, String pemPrivateKey, KeyAlgorithmEnums keyAlgorithm, X500NameInfo issuer, KeyUsage keyUsage, Date beginDate, Date endDate) throws Exception {
        long certKeyId = this.importPrivateKey(userId, pemPrivateKey, keyAlgorithm.getKeyAlgorithm());
        CertInfo certInfo = this.certHandler.createRootCert(userId, certKeyId, pemPrivateKey, keyAlgorithm, issuer, keyUsage, beginDate, endDate);
        return (CertVO)TransformUtils.simpleTransform(certInfo, CertVO.class);
    }

    public CertRequestVO createCertRequest(String userId, long issuerCertId, X500NameInfo subject) throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair();
        String pemPrivateKey = CertUtils.readPEMAsString(keyPair.getPrivate());
        return this.createCertRequest(userId, pemPrivateKey, KeyAlgorithmEnums.RSA, issuerCertId, subject);
    }

    public CertRequestVO createCertRequestByHexPriKey(String userId, String hexPrivateKey, KeyAlgorithmEnums keyAlgorithm, long issuerCertId, X500NameInfo subject) throws Exception {
        String pemPrivateKey = this.getPemPrivateKey(hexPrivateKey, keyAlgorithm);
        return this.createCertRequest(userId, pemPrivateKey, keyAlgorithm, issuerCertId, subject);
    }

    public CertRequestVO createCertRequest(String userId, String pemPrivateKey, KeyAlgorithmEnums keyAlgorithm, long issuerCertId, X500NameInfo subject) throws Exception {
        long certKeyId = this.importPrivateKey(userId, pemPrivateKey, keyAlgorithm.getKeyAlgorithm());
        CertRequestInfo requestInfo = this.certHandler.createCertRequest(userId, certKeyId, pemPrivateKey, keyAlgorithm, issuerCertId, subject);
        return (CertRequestVO)TransformUtils.simpleTransform(requestInfo, CertRequestVO.class);
    }

    public CertRequestVO createCertRequest(String userId, long certKeyId, long issuerCertId, X500NameInfo subject) throws Exception {
        CertRequestInfo requestInfo = this.certHandler.createCertRequest(userId, certKeyId, (String)null, (KeyAlgorithmEnums)null, issuerCertId, subject);
        return (CertRequestVO)TransformUtils.simpleTransform(requestInfo, CertRequestVO.class);
    }

    public CertVO createChildCert(String userId, int csrId) throws Exception {
        return this.createChildCert(userId, csrId, true);
    }

    public CertVO createChildCert(String userId, int csrId, boolean isCaCert) throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 315360000000L);
        return this.createChildCert(userId, csrId, isCaCert, beginDate, endDate);
    }

    public CertVO createChildCert(String userId, int csrId, boolean isCaCert, Date beginDate, Date endDate) throws Exception {
        return this.createChildCert(userId, csrId, isCaCert, (KeyUsage)null, beginDate, endDate);
    }

    public CertVO createChildCert(String userId, int csrId, boolean isCaCert, KeyUsage keyUsage, Date beginDate, Date endDate) throws Exception {
        CertInfo certInfo = this.certHandler.createChildCert(userId, csrId, isCaCert, keyUsage, beginDate, endDate);
        return (CertVO)TransformUtils.simpleTransform(certInfo, CertVO.class);
    }

    public void exportCertToFile(long certId, String filePath) throws Exception {
        CertVO certVO = this.queryCertInfoByCertId(certId);
        if (certVO != null && !StringUtils.isEmpty(certVO.getCertContent())) {
            CertUtils.writeCrt(CertUtils.convertStrToCert(certVO.getCertContent()), filePath);
        } else {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_NOT_EXIST);
        }
    }

    public CertVO resetCertificate(String userId, long certId) throws Exception {
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + 315360000000L);
        return this.resetCertificate(userId, certId, (KeyUsage)null, beginDate, endDate);
    }

    public CertVO resetCertificate(String userId, long certId, KeyUsage keyUsage, Date beginDate, Date endDate) throws Exception {
        CertInfo certInfo = this.certHandler.resetCertificate(userId, certId, keyUsage, beginDate, endDate);
        return (CertVO)TransformUtils.simpleTransform(certInfo, CertVO.class);
    }


    public List<CertVO> queryCertInfoList() {
        return queryCertList(null, null, null, null, null, null);
    }

    public List<CertVO> queryCertList(String userId, Long issuerKeyId, Long pCertId, String issuerOrg, String issuerCN, Boolean isCACert) {
        List<CertInfo> certInfos = this.certHandler.queryCertInfoList(userId, issuerKeyId, pCertId, issuerOrg, issuerCN, isCACert);
        return TransformUtils.simpleTransform(certInfos, CertVO.class);
    }

    public List<CertRequestVO> queryCertRequestList() {
        return queryCertRequestList(null, null, null, null, null, null);
    }

    public List<CertRequestVO> queryCertRequestList(String userId, Long subjectKeyId, Long pCertId, String subjectOrg, String subjectCN, String pCertUserId) {
        List<CertRequestInfo> certRequestInfos = this.certHandler.queryCertRequestList(userId, subjectKeyId, pCertId, subjectOrg, subjectCN, pCertUserId);
        return TransformUtils.simpleTransform(certRequestInfos, CertRequestVO.class);
    }

    public List<CertKeyVO> queryCertKeyList(String userId) {
        List<CertKeyInfo> certKeyInfos = this.certHandler.queryCertKeyList(userId);
        return TransformUtils.simpleTransform(certKeyInfos, CertKeyVO.class);
    }

    public CertVO queryCertInfoByCertId(long certId) {
        CertInfo certInfo = this.certHandler.queryCertInfoByCertId(certId);
        return (CertVO)TransformUtils.simpleTransform(certInfo, CertVO.class);
    }

    public CertRequestVO queryCertRequestByCsrId(long csrId) {
        CertRequestInfo certRequestInfo = this.certHandler.queryCertRequestByCsrId(csrId);
        return (CertRequestVO)TransformUtils.simpleTransform(certRequestInfo, CertRequestVO.class);
    }

    public long importPrivateKey(String userId, String pemPrivateKey, String priAlg) throws Exception {
        return this.certHandler.importPrivateKey(userId, pemPrivateKey, priAlg);
    }

    public void deleteKey(long pkId) {
        this.certHandler.deleteKey(pkId);
    }

    private String getPemPrivateKey(String hexPrivateKey, KeyAlgorithmEnums keyAlgorithm) throws Exception {
        String pemPrivate = null;
        byte[] privateByte = Numeric.hexStringToByteArray(hexPrivateKey);
        if (keyAlgorithm.equals(KeyAlgorithmEnums.ECDSA)) {
            BigInteger key = Numeric.toBigInt(privateByte);
            BigInteger pubKey = create(privateByte).getPublicKey();
            ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid("secp256k1");
            X962Parameters params = new X962Parameters(curveOid);
            ECPrivateKey keyStructure = new ECPrivateKey(256, key, new DERBitString(get65BytePubKey(BigIntegers.asUnsignedByteArray(pubKey))), (ASN1Encodable)null);
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), keyStructure);
            PrivateKey privateKey = KeyFactory.getInstance("EC", "BC").generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
            pemPrivate = CertUtils.readPEMAsString(privateKey);
        } else if (keyAlgorithm.equals(KeyAlgorithmEnums.RSA)) {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateByte);
            pemPrivate = CertUtils.readPEMAsString(KeyFactory.getInstance("RSA").generatePrivate(keySpec));
        }

        return pemPrivate;
    }

    private static ECKeyPair create(byte[] privKeyBytes) throws Exception {
        return ECKeyPair.create(privKeyBytes);
    }

    private static byte[] get65BytePubKey(byte[] pubKey) {
        if (pubKey.length != 64) {
            throw new RuntimeException("pubKey length not 64");
        } else {
            byte[] bytes = new byte[65];
            bytes[0] = 4;
            System.arraycopy(pubKey, 0, bytes, 1, pubKey.length);
            return bytes;
        }
    }
}
