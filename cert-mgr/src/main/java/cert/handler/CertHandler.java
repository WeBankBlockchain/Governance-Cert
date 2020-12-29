package cert.handler;

import cert.db.cert.entity.CertInfo;
import cert.db.cert.entity.CertKeyInfo;
import cert.db.cert.entity.CertRequestInfo;
import cert.db.dao.CertDao;
import cert.enums.CertDigestAlgEnums;
import cert.enums.KeyAlgorithmEnums;
import cert.enums.MgrExceptionCodeEnums;
import cert.exception.CertMgrException;
import com.webank.cert.handler.X509CertHandler;
import com.webank.cert.model.X500NameInfo;
import com.webank.cert.service.CertService;
import com.webank.cert.utils.CertUtils;
import com.webank.cert.utils.KeyUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;


/**
 * @author wesleywang
 * @Description:
 * @date 2020-05-19
 */
@Service
@Slf4j
public class CertHandler {


    @Autowired
    private CertService certService;
    @Autowired
    private CertDao certDao;


    public long importPrivateKey(String userId, String pemPrivateKey, String priAlg) throws Exception {
        if (StringUtils.isBlank(userId)) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_ACCOUNT_NOT_EXIST);
        }
        try {
            KeyPair keyPair = KeyUtils.getRSAKeyPair(pemPrivateKey);
        }catch (Exception e){
            log.error("importPrivateKey failed, reason :", e);
            return 0;
        }
        CertKeyInfo certKeyInfo = new CertKeyInfo();
        certKeyInfo.setKeyAlg(priAlg);
        certKeyInfo.setKeyPem(pemPrivateKey);
        certKeyInfo.setUserId(userId);
        certKeyInfo = certDao.save(certKeyInfo);
        return certKeyInfo.getPkId();
    }

    public void deleteKey(long pkId){
        certDao.deleteKey(pkId);
    }


    @Transactional
    public CertInfo createRootCert(String userId, long certKeyId, String pemPrivateKey, KeyAlgorithmEnums keyAlgorithm,
                                   X500NameInfo issuer, KeyUsage keyUsage, Date beginDate, Date endDate)
            throws Exception {
        if (StringUtils.isBlank(userId)){
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_ACCOUNT_NOT_EXIST);
        }
        if (certKeyId > 0 && pemPrivateKey == null) {
            CertKeyInfo certKeyInfo = certDao.findCertKeyById(certKeyId);
            pemPrivateKey = certKeyInfo.getKeyPem();
            keyAlgorithm = KeyAlgorithmEnums.getByKeyAlg(certKeyInfo.getKeyAlg());
        }
       CertDigestAlgEnums certDigestAlgEnums = getCertDigestAlg(keyAlgorithm);
        KeyPair keyPair = getKeyPair(keyAlgorithm, pemPrivateKey);

        X509Certificate certificate = certService.createRootCertificate(certDigestAlgEnums.getAlgorithmName(),
                issuer, keyUsage, beginDate, endDate, keyPair.getPublic(), keyPair.getPrivate());
        String certStr = CertUtils.readPEMAsString(certificate);

        return certDao.save(buildCertInfo(certStr, issuer.getCommonName(),
                issuer.getOrganizationName(), issuer.getCommonName(), issuer.getOrganizationName(),
                keyPair.getPublic(), userId, certificate.getSerialNumber(), certKeyId,
                certKeyId, true, 0));
    }

    @Transactional
    public CertRequestInfo createCertRequest(String userId, long certKeyId, String pemPrivateKey, KeyAlgorithmEnums keyAlgorithm,
                                             long parentCertId, X500NameInfo subject)
            throws Exception {
        if (StringUtils.isBlank(userId)){
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_ACCOUNT_NOT_EXIST);
        }
        if (certKeyId > 0 && pemPrivateKey == null) {
            CertKeyInfo certKeyInfo = certDao.findCertKeyById(certKeyId);
            pemPrivateKey = certKeyInfo.getKeyPem();
            keyAlgorithm = KeyAlgorithmEnums.getByKeyAlg(certKeyInfo.getKeyAlg());
        }
        CertDigestAlgEnums certDigestAlgEnums = getCertDigestAlg(keyAlgorithm);
        KeyPair keyPair = getKeyPair(keyAlgorithm, pemPrivateKey);

        PKCS10CertificationRequest request = certService.createCertRequest(subject, keyPair.getPublic(),
                keyPair.getPrivate(), certDigestAlgEnums.getAlgorithmName());
        String csrStr = CertUtils.readPEMAsString(request);

        CertInfo certInfo = certDao.findCertById(parentCertId);
        return certDao.save(buildCertRequestInfo(csrStr, subject.getCommonName(), subject.getOrganizationName(),
                parentCertId, userId, certKeyId, certInfo.getUserId()));
    }

    @Transactional
    public CertInfo createChildCert(String userId, int csrId, boolean isCaCert, KeyUsage keyUsage,
                                  Date beginDate, Date endDate)
            throws Exception {
        if (StringUtils.isBlank(userId)){
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_ACCOUNT_NOT_EXIST);
        }
        CertRequestInfo requestInfo = certDao.findCertRequestById(csrId);
        if (requestInfo == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_REQUEST_NOT_EXIST);
        }
        CertInfo certInfo = certDao.findCertById(requestInfo.getPCertId());
        if (certInfo == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_NOT_EXIST);
        }
        CertKeyInfo keyInfo = certDao.findCertKeyById(certInfo.getIssuerKeyId());
        if (keyInfo == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_NOT_EXIST);
        }

        KeyAlgorithmEnums keyAlgorithm = KeyAlgorithmEnums.getByKeyAlg(keyInfo.getKeyAlg());
        CertDigestAlgEnums certDigestAlgEnums = getCertDigestAlg(keyAlgorithm);
        KeyPair keyPair = getKeyPair(keyAlgorithm, keyInfo.getKeyPem());

        X509Certificate parentCertificate = CertUtils.convertStrToCert(certInfo.getCertContent());
        try {
            parentCertificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_VALIDITY_FAILURE);
        }

        X509Certificate certificate = certService.createChildCertificate(isCaCert,
                certDigestAlgEnums.getAlgorithmName(), parentCertificate,
                CertUtils.convertStrToCsr(requestInfo.getCertRequestContent()),
                keyUsage, beginDate, endDate, keyPair.getPrivate());

        requestInfo.setIssue(true);
        certDao.save(requestInfo);
        return certDao.save(buildCertInfo(CertUtils.readPEMAsString(certificate), certInfo.getIssuerCN(),
                certInfo.getIssuerOrg(), requestInfo.getSubjectCN(), requestInfo.getSubjectOrg(),
                certificate.getPublicKey(), userId, certificate.getSerialNumber(), keyInfo.getPkId(),
                requestInfo.getSubjectKeyId(), isCaCert, certInfo.getPkId()));
    }

    @Transactional
    public CertInfo resetCertificate(String userId, long certId, KeyUsage keyUsage,
                                   Date beginDate, Date endDate)
            throws Exception {
        if (StringUtils.isBlank(userId)){
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_ACCOUNT_NOT_EXIST);
        }
        CertInfo certInfo = certDao.findCertById(certId);
        if (certInfo == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_NOT_EXIST);
        }
        CertKeyInfo keyInfo = certDao.findCertKeyById(certInfo.getIssuerKeyId());
        if (keyInfo == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_NOT_EXIST);
        }

        X509Certificate certificate = CertUtils.convertStrToCert(certInfo.getCertContent());

        KeyAlgorithmEnums keyAlgorithm = KeyAlgorithmEnums.getByKeyAlg(keyInfo.getKeyAlg());
        CertDigestAlgEnums certDigestAlgEnums = getCertDigestAlg(keyAlgorithm);
        KeyPair keyPair = getKeyPair(keyAlgorithm, keyInfo.getKeyPem());

        X509Certificate reCert = null;
        if (certInfo.getSubjectKeyId().equals(certInfo.getIssuerKeyId())) {
            reCert = X509CertHandler.createRootCert(certDigestAlgEnums.getAlgorithmName(),
                    X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded()), null,
                    beginDate, endDate, certificate.getPublicKey(), keyPair.getPrivate());
        } else {
            CertInfo parentCertInfo = certDao.findCertById(certInfo.getPCertId());
            if (parentCertInfo == null) {
                throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_NOT_EXIST);
            }

            CertRequestInfo requestInfo = certDao.findByPCertIdAndSubjectKeyId(
                    certInfo.getPCertId(), certInfo.getSubjectKeyId());
            if (requestInfo == null) {
                throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_REQUEST_NOT_EXIST);
            }

            X509Certificate parentCert = CertUtils.convertStrToCert(parentCertInfo.getCertContent());
            reCert = X509CertHandler.createChildCert(certInfo.getIsCACert(), certDigestAlgEnums.getAlgorithmName(),
                    parentCert, CertUtils.convertStrToCsr(requestInfo.getCertRequestContent()),
                    keyUsage, beginDate, endDate, keyPair.getPrivate());
        }

        String reCertStr = CertUtils.readPEMAsString(reCert);
        certInfo.setUserId(userId);
        certInfo.setCertContent(reCertStr);
        return certDao.save(certInfo);
    }


    public List<CertInfo> queryCertInfoList(String userId, Long issuerKeyId, Long pCertId, String issuerOrg,
                                            String issuerCN, Boolean isCACert) {

        return certDao.findCertList(userId, issuerKeyId, pCertId, issuerOrg, issuerCN, isCACert);
    }


    public List<CertRequestInfo> queryCertRequestList(String userId, Long subjectKeyId, Long pCertId,
                                                      String subjectOrg, String subjectCN, String pCertUserId) {
        return certDao.findCertRequestList(userId, subjectKeyId, pCertId, subjectOrg, subjectCN, pCertUserId);
    }

    public List<CertKeyInfo> queryCertKeyList(String userId) {
        return certDao.findKeyByUserId(userId);
    }


    public CertInfo queryCertInfoByCertId(long certId) {
        return certDao.findCertById(certId);
    }

    public CertRequestInfo queryCertRequestByCsrId(long csrId) {
        return certDao.findCertRequestById(csrId);
    }


    private CertDigestAlgEnums getCertDigestAlg(KeyAlgorithmEnums keyAlgorithm) throws CertMgrException {
        if (keyAlgorithm == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_ALG_NOT_EXIST);
        }
        CertDigestAlgEnums certDigestAlgEnums = CertDigestAlgEnums.getByKeyAlg(keyAlgorithm.getKeyAlgorithm());
        if (certDigestAlgEnums == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_ALG_NOT_EXIST);
        }
        return certDigestAlgEnums;
    }


    private KeyPair getKeyPair(KeyAlgorithmEnums keyAlgorithm, String pemPrivateKey) throws Exception {
        KeyPair keyPair = null;
        if (keyAlgorithm.equals(KeyAlgorithmEnums.ECDSA) || keyAlgorithm.equals(KeyAlgorithmEnums.SM2)) {
            keyPair = KeyUtils.getECKeyPair(pemPrivateKey);
        }
        if (keyAlgorithm.equals(KeyAlgorithmEnums.RSA)) {
            keyPair = KeyUtils.getRSAKeyPair(pemPrivateKey);
        }
        if (keyPair == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_ALG_NOT_EXIST);
        }
        return keyPair;
    }

    private CertInfo buildCertInfo(String certificate, String issuerCommonName, String issuerOrgName,
                                   String subjectCommonName, String subjectOrgName, PublicKey publicKey,
                                   String userId, BigInteger serialNumber, long certKeyId, long subjectKeyId,
                                   boolean isCACert, long issuerCertId) {
        CertInfo certInfo = new CertInfo();
        certInfo.setUserId(userId);
        certInfo.setIssuerKeyId(certKeyId);
        certInfo.setSubjectKeyId(subjectKeyId);
        certInfo.setCertContent(certificate);
        certInfo.setIssuerCN(issuerCommonName);
        certInfo.setIssuerOrg(issuerOrgName);
        certInfo.setSubjectCN(subjectCommonName);
        certInfo.setSubjectOrg(subjectOrgName);
        certInfo.setSubjectPubKey(CertUtils.readPEMAsString(publicKey));
        certInfo.setSerialNumber(String.valueOf(serialNumber));
        certInfo.setIsCACert(isCACert);
        certInfo.setPCertId(issuerCertId);
        return certInfo;
    }

    private CertRequestInfo buildCertRequestInfo(String csrStr, String commonName, String organizationName,
                                                 long parentCertId, String userId, long certKeyId, String pCertUserId) {
        CertRequestInfo certRequestInfo = new CertRequestInfo();
        certRequestInfo.setUserId(userId);
        certRequestInfo.setPCertId(parentCertId);
        certRequestInfo.setSubjectKeyId(certKeyId);
        certRequestInfo.setSubjectCN(commonName);
        certRequestInfo.setSubjectOrg(organizationName);
        certRequestInfo.setCertRequestContent(csrStr);
        certRequestInfo.setPCertUserId(pCertUserId);
        certRequestInfo.setIssue(false);
        return certRequestInfo;
    }

}
