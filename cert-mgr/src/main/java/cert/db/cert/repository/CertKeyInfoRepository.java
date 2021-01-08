package cert.db.cert.repository;

import cert.db.cert.entity.CertKeyInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author wesleywang
 */
@Repository
public interface CertKeyInfoRepository extends JpaRepository<CertKeyInfo, Long>,
        JpaSpecificationExecutor<CertKeyInfo> {

    CertKeyInfo findByPkId(long pkId);

    List<CertKeyInfo> findByUserId(String userId);

}
