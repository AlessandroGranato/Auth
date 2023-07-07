package com.pyrosandro.auth.exception;

import com.pyrosandro.common.error.GlobalExceptionHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import java.util.Locale;

@Slf4j
@ControllerAdvice
public class AuthExceptionHandler extends GlobalExceptionHandler {

    public AuthExceptionHandler(@Value("${common.printstacktrace:false}") boolean printStackTrace, MessageSource messageSource) {
        super(printStackTrace, messageSource);
    }


    @ExceptionHandler({AuthException.class})
    public ResponseEntity<Object> handleAuthException(AuthException ex, WebRequest request) {

        switch (ex.getErrorCode()) {
            case RESOURCE_NOT_FOUND:
                log.error("Resource not found", ex);
                return buildErrorDTO(ex, messageSource.getMessage(String.valueOf(ex.getErrorCode().getCode()), ex.getErrorArgs(), Locale.getDefault()), HttpStatus.NOT_FOUND, request);
            case INVALID_JWT_SIGNATURE:
            case MALFORMED_JWT:
            case EXIPERD_JWT:
            case UNSUPPORTED_JWT:
            case ILLEGAL_JWT_ARGUMENT:
            case MISSING_AUTHORIZATION_HEADER:
            case RESOURCE_NOT_AUTHORIZED:
                log.error("unauthorized access", ex);
                return buildErrorDTO(ex, messageSource.getMessage(String.valueOf(ex.getErrorCode().getCode()), ex.getErrorArgs(), Locale.getDefault()), HttpStatus.UNAUTHORIZED, request);
            case USERNAME_ALREADY_USED:
            case EMAIL_ALREADY_USED:
                log.error("bad request", ex);
                return buildErrorDTO(ex, messageSource.getMessage(String.valueOf(ex.getErrorCode().getCode()), ex.getErrorArgs(), Locale.getDefault()), HttpStatus.BAD_REQUEST, request);
            default:
                log.error("generic error", ex);
                return buildErrorDTO(ex, HttpStatus.INTERNAL_SERVER_ERROR, request);
        }
    }
}
