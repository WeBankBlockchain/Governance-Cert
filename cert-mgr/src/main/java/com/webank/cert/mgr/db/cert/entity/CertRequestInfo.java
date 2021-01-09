package com.webank.cert.mgr.db.cert.entity;

import com.webank.cert.mgr.db.entity.IdEntity;
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
 */
@Data
@Accessors(chain = true)
@Entity(name = "cert_request_info")
@Table(name = "cert_request_info", indexes = { @Index(name = "user_id", columnList = "user_id"),
        @Index(name = "subject_key_id", columnList = "subject_key_id"),
        @Index(name = "parent_cert_id", columnList = "parent_cert_id"),
        @Index(name = "subject_org", columnList = "subject_org"),
        @Index(name = "subject_cn", columnList = "subject_cn")
})
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class CertRequestInfo extends IdEntity {

    @Column(name = "user_id")
    private String userId;

    @Column(name = "subject_key_id")
    private Long subjectKeyId;

    @Column(name = "cert_request_content")
    @Lob
    private String certRequestContent;

    @Column(name = "parent_cert_id")
    private Long pCertId;

    @Column(name = "parent_cert_user_id")
    private String pCertUserId;

    @Column(name = "subject_org")
    private String subjectOrg;

    @Column(name = "subject_cn")
    private String subjectCN;

    @Column(name = "issue")
    private Boolean issue;
}
