package cert.model.vo;

import lombok.Data;

import java.io.Serializable;

/**
 * @author wesleywang
 * @Description:
 * @date 2020-05-20
 */
@Data
public class CertVO implements Serializable {

    private Long pkId;

    private String userId;

    private String subjectPubKey;

    private String serialNumber;

    private String certContent;

    private Long pCertId;

    private String issuerOrg;

    private String issuerCN;

    private String subjectOrg;

    private String subjectCN;

    private Boolean isCACert;

    private Long issuerKeyId;

    private Long subjectKeyId;

}
