package cert.db.cert.entity;

import cert.db.entity.IdEntity;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Index;
import javax.persistence.Lob;
import javax.persistence.Table;

/**
 * @author wesleywang
 * @Description:
 * @date 2020-05-19
 */
@Data
@Accessors(chain = true)
@Entity(name = "cert_info")
@Table(name = "cert_info", indexes = { @Index(name = "user_id", columnList = "user_id"),
        @Index(name = "issuer_key_id", columnList = "issuer_key_id"),
        @Index(name = "subject_key_id", columnList = "subject_key_id"),
        @Index(name = "serial_number", columnList = "serial_number"),
        @Index(name = "parent_cert_id", columnList = "parent_cert_id"),
        @Index(name = "issuer_org", columnList = "issuer_org"),
        @Index(name = "issuer_cn", columnList = "issuer_cn"),
        @Index(name = "subject_org", columnList = "subject_org"),
        @Index(name = "subject_cn", columnList = "subject_cn"),
        @Index(name = "is_ca_cert", columnList = "is_ca_cert")

})
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class CertInfo extends IdEntity {


    @Column(name = "user_id")
    private String userId;

    @Column(name = "issuer_key_id")
    private Long issuerKeyId;

    @Column(name = "subject_key_id")
    private Long subjectKeyId;

    @Column(name = "subject_pub_key")
    @Lob
    private String subjectPubKey;

    @Column(name = "serial_number")
    private String serialNumber;

    @Column(name = "cert_content")
    @Lob
    private String certContent;

    @Column(name = "parent_cert_id")
    private Long pCertId;

    @Column(name = "issuer_org")
    private String issuerOrg;

    @Column(name = "issuer_cn")
    private String issuerCN;

    @Column(name = "subject_org")
    private String subjectOrg;

    @Column(name = "subject_cn")
    private String subjectCN;

    @Column(name = "is_ca_cert")
    private Boolean isCACert;
}

