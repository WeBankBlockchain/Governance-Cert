package cert.model.vo;

import lombok.Data;

import java.io.Serializable;

/**
 * @author wesleywang
 * @Description:
 * @date 2020-05-20
 */
@Data
public class CertKeyVO implements Serializable {

    private Long pkId;

    private String userId;

    private String keyAlg;

    private String keyPem;
}
