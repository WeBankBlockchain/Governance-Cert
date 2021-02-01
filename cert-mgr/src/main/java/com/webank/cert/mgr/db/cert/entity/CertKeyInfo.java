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
@Entity(name = "cert_keys_info")
@Table(name = "cert_keys_info", indexes = { @Index(name = "user_id", columnList = "user_id")})
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class CertKeyInfo extends IdEntity {

    @Column(name = "key_pem")
    @Lob
    private String keyPem;

    @Column(name = "user_id")
    private String userId;

    @Column(name = "key_alg")
    private String keyAlg;


}

