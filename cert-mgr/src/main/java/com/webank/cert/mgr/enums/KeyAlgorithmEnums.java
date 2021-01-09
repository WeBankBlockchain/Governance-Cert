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
public enum KeyAlgorithmEnums {

    RSA("RSA"),
    ECDSA("ECDSA"),
    SM2("SM2");

    private String keyAlgorithm;

    public static KeyAlgorithmEnums getByKeyAlg(String keyAlgorithm){
        for(KeyAlgorithmEnums type : KeyAlgorithmEnums.values()){
            if(type.getKeyAlgorithm().equals(keyAlgorithm)){
                return type;
            }
        }
        log.error("keyAlgorithm type {} can't be converted.", keyAlgorithm);
        return null;
    }
}
