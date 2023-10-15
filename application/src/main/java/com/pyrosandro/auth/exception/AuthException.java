package com.pyrosandro.auth.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class AuthException extends Exception {

    private final AuthErrorConstants errorCode;
    private final Object[] errorArgs;

    public AuthException(AuthErrorConstants errorCode, Object[] errorArgs) {
        this.errorCode = errorCode;
        this.errorArgs = errorArgs;
    }
}
