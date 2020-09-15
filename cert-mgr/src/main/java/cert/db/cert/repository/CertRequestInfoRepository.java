package cert.db.cert.repository;

import cert.db.cert.entity.CertRequestInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020-05-19
 */
@Repository
public interface CertRequestInfoRepository extends JpaRepository<CertRequestInfo, Long>,
        JpaSpecificationExecutor<CertRequestInfo> {

    CertRequestInfo findByPkId(long pkId);

    CertRequestInfo findBypCertIdAndSubjectKeyId(Long pCertId, Long subjectKeyId);


    @Query(value = "select * from cert_request_info where if(?1 !='',user_id=?1,1=1) and " +
            "if(?2 !='',subject_key_id=?2,1=1) and " +
            "if(?3 !='',parent_cert_id=?3,1=1) and " +
            "if(?4 !='',subject_org=?4,1=1) and " +
            "if(?5 !='',subject_cn=?5,1=1) and " +
            "if(?6 !='',parent_cert_userId=?6,1=1) ", nativeQuery = true)
    List<CertRequestInfo> findCertRequestList(String userId,
                                              Long subjectKeyId,
                                              Long pCertId,
                                              String subjectOrg,
                                              String subjectCN,
                                              String pCertUserId);


}
