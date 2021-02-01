package com.webank.cert.mgr.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

/**
 * @author wesleywang
 */
@Getter
@ToString
@AllArgsConstructor
@Slf4j
public enum CertDigestAlgEnums {

    SHA256WITHRSA("RSA", "SHA256WITHRSA"),
    SHA256WITHECDSA("ECDSA", "SHA256WITHECDSA"),
    SM3WITHSM2("SM2","SM3WITHSM2");

    private String keyAlgorithm;
    private String algorithmName;

    public static CertDigestAlgEnums getByKeyAlg(String keyAlgorithm){
        for(CertDigestAlgEnums type : CertDigestAlgEnums.values()){
            if(type.getKeyAlgorithm().equals(keyAlgorithm)){
                return type;
            }
        }
        log.error("keyAlgorithm type {} can't be converted.", keyAlgorithm);
        return null;
    }

    public static CertDigestAlgEnums getByAlgName(String algorithmName){
        for(CertDigestAlgEnums type : CertDigestAlgEnums.values()){
            if(type.getAlgorithmName().equals(algorithmName)){
                return type;
            }
        }
        log.error("algorithmName type {} error.", algorithmName);
        return null;
    }
}
