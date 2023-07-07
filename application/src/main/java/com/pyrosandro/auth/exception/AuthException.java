package com.pyrosandro.auth.exception;

import lombok.Data;

@Data
public class AuthException extends Exception {

    private final ErrorConstants errorCode;
    private final Object[] errorArgs;

    //Use this constructor when you know exactly what kind of exception to catch
    //ex: throw new AuthException(ErrorConstants.UNAUTHORIZED, null);
    public AuthException(ErrorConstants errorCode, Object[] errorArgs) {
        this.errorCode = errorCode;
        this.errorArgs = errorArgs;
    }

    //Use this constructor when you catch a generic Exception
    //ex: throw new AuthException(ErrorConstants.UNAUTHORIZED, null, e.getMessage(), e);
    public AuthException(ErrorConstants errorCode, Object[] errorArgs, String errorMessage, Throwable throwable) {
        super(errorMessage, throwable);
        this.errorCode = errorCode;
        this.errorArgs = errorArgs;
    }





}
