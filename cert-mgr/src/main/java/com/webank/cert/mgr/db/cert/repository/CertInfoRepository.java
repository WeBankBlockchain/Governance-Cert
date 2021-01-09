package com.webank.cert.mgr.db.cert.repository;

import com.webank.cert.mgr.db.cert.entity.CertInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author wesleywang
 */
@Repository
public interface CertInfoRepository extends JpaRepository<CertInfo, Long>, JpaSpecificationExecutor<CertInfo> {


    CertInfo findByPkId(long pkId);

    List<CertInfo> findBypCertId(Long PCertId);

    List<CertInfo> findByIsCACert(Boolean isCACert);


    @Query(value = "select * from cert_info where if(?1 !='',user_id=?1,1=1) and " +
            " if(?2 !='',issuer_key_id=?2,1=1) and " +
            "if(?3 !='',parent_cert_id=?3,1=1) and " +
            "if(?4 !='',issuer_org=?4,1=1) and " +
            "if(?5 !='',issuer_cn=?5,1=1) and " +
            "if(?6 !='',is_ca_cert=?6,1=1)", nativeQuery = true)
    List<CertInfo> findCertList(String userId,
                                Long issuerKeyId,
                                Long pCertId,
                                String issuerOrg,
                                String issuerCN,
                                Boolean isCACert);

}
