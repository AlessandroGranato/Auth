package com.pyrosandro.auth.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum ErrorConstants {

    OK(0),
    GENERIC_ERROR(100),
    RESOURCE_NOT_FOUND(101),
    INVALID_JWT_SIGNATURE(102),
    MALFORMED_JWT(103),
    EXIPERD_JWT(104),
    UNSUPPORTED_JWT(105),
    ILLEGAL_ARGUMENT(106),
    MISSING_AUTHORIZATION_HEADER(107),
    RESOURCE_NOT_AUTHORIZED(108),
    USERNAME_ALREADY_USED(109),
    EMAIL_ALREADY_USED(110),
    CONSTRAINT_VALIDATION_ERROR(111),
    METHOD_ARGUMENT_NOT_VALID(112),
    USERNAME_NOT_FOUND(113),
    ROLE_NOT_FOUND(114),
    ;

    public final int code;

}