package cert.model.vo;

import lombok.Data;

import java.io.Serializable;

/**
 * @author wesleywang
 * @Description:
 * @date 2020-05-20
 */
@Data
public class CertRequestVO implements Serializable {

    private Long pkId;

    private String userId;

    private Long subjectKeyId;

    private String certRequestContent;

    private Long pCertId;

    private String subjectOrg;

    private String subjectCN;

    private Boolean issue;

    private String pCertUserId;

}
