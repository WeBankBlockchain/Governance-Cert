/**
 * Copyright (C) 2018 webank, Inc. All Rights Reserved.
 */

package com.webank.cert.mgr.db.entity;

import lombok.Data;
import lombok.experimental.Accessors;

import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;
import java.io.Serializable;

/**
 * 
 * IdEntity
 *
 * @author graysonzhang
 *
 */
@Data
@MappedSuperclass
@Accessors(chain = true)
public abstract class IdEntity implements Serializable {

    private static final long serialVersionUID = 5903397383140175895L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "pk_id")
    protected Long pkId;
}
