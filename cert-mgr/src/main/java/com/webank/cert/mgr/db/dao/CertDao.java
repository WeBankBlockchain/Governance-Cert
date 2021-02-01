package com.webank.cert.mgr.db.dao;

import com.webank.cert.mgr.db.cert.entity.CertInfo;
import com.webank.cert.mgr.db.cert.entity.CertKeyInfo;
import com.webank.cert.mgr.db.cert.entity.CertRequestInfo;
import com.webank.cert.mgr.db.cert.repository.CertInfoRepository;
import com.webank.cert.mgr.db.cert.repository.CertKeyInfoRepository;
import com.webank.cert.mgr.db.cert.repository.CertRequestInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;


/**
 * @author wesleywang
 */
@Service
public class CertDao {

    @Autowired
    private CertInfoRepository certInfoRepository;
    @Autowired
    private CertRequestInfoRepository certRequestInfoRepository;
    @Autowired
    private CertKeyInfoRepository certKeyInfoRepository;



    public CertKeyInfo save(CertKeyInfo certKeyInfo){
        return certKeyInfoRepository.save(certKeyInfo);
    }

    public CertInfo save(CertInfo certInfo){
        return certInfoRepository.save(certInfo);
    }

    public CertRequestInfo save(CertRequestInfo certRequestInfo){
        return certRequestInfoRepository.save(certRequestInfo);
    }

    public void deleteKey(long pkId){
        certKeyInfoRepository.deleteById(pkId);
    }

    public CertKeyInfo findCertKeyById(long certKeyId){
        return certKeyInfoRepository.findByPkId(certKeyId);
    }


    public CertRequestInfo findCertRequestById(long csrId){
        return certRequestInfoRepository.findByPkId(csrId);
    }

    public CertRequestInfo findByPCertIdAndSubjectKeyId(Long PCertId, Long subjectKeyId){
        return certRequestInfoRepository.findBypCertIdAndSubjectKeyId(PCertId,subjectKeyId);
    }

    public CertInfo findCertById(long certId){
        return certInfoRepository.findByPkId(certId);
    }

    public List<CertInfo> findCertList(String userId, Long issuerKeyId, Long pCertId, String issuerOrg,
                                       String issuerCN, Boolean isCACert){
        return certInfoRepository.findCertList(userId, issuerKeyId, pCertId, issuerOrg, issuerCN, isCACert);
    }

    public List<CertRequestInfo> findCertRequestList(String userId, Long subjectKeyId, Long pCertId,
                                                     String subjectOrg, String subjectCN, String pCertUserId){
        return certRequestInfoRepository.findCertRequestList(userId, subjectKeyId, pCertId, subjectOrg, subjectCN, pCertUserId);
    }

    public List<CertKeyInfo> findKeyByUserId(String userId){
        return certKeyInfoRepository.findByUserId(userId);
    }
}
