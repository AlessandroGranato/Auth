package com.pyrosandro.auth.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum AuthErrorConstants {

    RESOURCE_NOT_FOUND(1001),
    INVALID_JWT_SIGNATURE(1002),
    MALFORMED_JWT(1003),
    EXIPERD_JWT(1004),
    UNSUPPORTED_JWT(1005),
    ILLEGAL_JWT_ARGUMENT(1006),
    MISSING_AUTHORIZATION_HEADER(1007),
    RESOURCE_NOT_AUTHORIZED(1008),
    USERNAME_ALREADY_USED(1009),
    EMAIL_ALREADY_USED(1010),
    METHOD_ARGUMENT_NOT_VALID(1011),
    USERNAME_NOT_FOUND(1012),
    ROLE_NOT_FOUND(1013),
    ;

    public final int code;

}