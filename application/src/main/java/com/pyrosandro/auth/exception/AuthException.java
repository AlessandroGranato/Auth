package com.pyrosandro.auth.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.http.HttpStatus;

@Data
@EqualsAndHashCode(callSuper = true)
public class AuthException extends Exception {

    private final AuthErrorConstants errorCode;
    private final Object[] errorArgs;
    private final HttpStatus httpStatus;

    public AuthException(AuthErrorConstants errorCode, Object[] errorArgs, HttpStatus httpStatus) {
        this.errorCode = errorCode;
        this.errorArgs = errorArgs;
        this.httpStatus = httpStatus;
    }
}
