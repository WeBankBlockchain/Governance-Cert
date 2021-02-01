package com.webank.cert.mgr.model;

import com.webank.cert.mgr.exception.CertMgrException;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author aaronchu
 */
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CommonResponse<TBody> {

    private static final int SUCCESS_CODE = 0;

    private int code;

    private String message;

    private TBody data;

    public static <T> CommonResponse success(T data){
        return new CommonResponse(SUCCESS_CODE, "", data);
    }

    public static CommonResponse fail(Exception error){
        if(error instanceof CertMgrException){
            CertMgrException certException = (CertMgrException)error;
            return new CommonResponse(certException.getCodeMessageEnums().getExceptionCode(),
                    certException.getCodeMessageEnums().getExceptionMessage(), null);
        }
        return new CommonResponse(-1, error.getMessage(), null);
    }
}
