package com.pyrosandro.auth.exception;

import com.pyrosandro.common.error.GlobalExceptionHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
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
        return buildErrorDTO(ex, messageSource.getMessage(String.valueOf(ex.getErrorCode().getCode()), ex.getErrorArgs(), Locale.getDefault()), ex.getHttpStatus(), request);
    }

    @ExceptionHandler({AccessDeniedException.class})
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<Object> handleForbiddenException(AccessDeniedException ex, WebRequest request) {
        log.error("forbidden access", ex);
        return this.buildErrorDTO(ex, HttpStatus.FORBIDDEN, request);
    }


    @ExceptionHandler({AuthenticationException.class, AuthenticationCredentialsNotFoundException.class, BadCredentialsException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseEntity<Object> handleUnauthorizedException(AuthenticationException ex, WebRequest request) {
        log.error("AuthenticationException access", ex);
        return this.buildErrorDTO(ex, HttpStatus.UNAUTHORIZED, request);
    }
}
