package com.pyrosandro.auth.exception;

import com.pyrosandro.auth.dto.response.ErrorDTO;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Locale;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private final boolean printStackTrace;

    private final MessageSource messageSource;

    public GlobalExceptionHandler(@Value("${common.printstacktrace:false}") boolean printStackTrace, MessageSource messageSource) {
        this.printStackTrace = printStackTrace;
        this.messageSource = messageSource;
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
            case ILLEGAL_ARGUMENT:
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

    @ExceptionHandler(RuntimeException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<Object> handleAllUncaughtRuntimeExceptions(RuntimeException ex, WebRequest request) {
        log.error("Unknown error occurred", ex);
        return buildErrorDTO(ex, HttpStatus.INTERNAL_SERVER_ERROR, request);
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<Object> handleAllUncaughtExceptions(Exception ex, WebRequest request) {
        log.error("Unknown error occurred", ex);
        return buildErrorDTO(ex, HttpStatus.INTERNAL_SERVER_ERROR, request);
    }

    @Override
    public ResponseEntity<Object> handleExceptionInternal(Exception ex, @Nullable Object body, HttpHeaders headers, HttpStatus status, WebRequest request) {
        return buildErrorDTO(ex,status,request);
    }

    private ResponseEntity<Object> buildErrorDTO(Exception ex, String message, HttpStatus status, WebRequest request) {
        ErrorDTO errorDTO = new ErrorDTO(status, message);
        if (printStackTrace) {
            errorDTO.setStackTrace(ExceptionUtils.getStackTrace(ex));
        }
        return ResponseEntity.status(status).body(errorDTO);
    }

    private ResponseEntity<Object> buildErrorDTO(Exception ex, HttpStatus status, WebRequest request) {
        ErrorDTO errorDTO = new ErrorDTO(status, ex.getMessage());
        if (printStackTrace) {
            errorDTO.setStackTrace(ExceptionUtils.getStackTrace(ex));
        }
        return ResponseEntity.status(status).body(errorDTO);
    }

}

//@Slf4j
//@ControllerAdvice
//public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {
//
//    @Value("${common.printstacktrace:false}")
//    private boolean printStackTrace;
//
//    @ExceptionHandler(ResourceNotFoundException.class)
//    @ResponseStatus(HttpStatus.NOT_FOUND)
//    public ResponseEntity<Object> handleResourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {
//        log.error("Resource not found", ex);
//        return buildErrorDTO(ex, HttpStatus.NOT_FOUND, request);
//    }
//
//    @ExceptionHandler(RuntimeException.class)
//    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
//    public ResponseEntity<Object> handleAllUncaughtRuntimeExceptions(RuntimeException ex, WebRequest request) {
//        log.error("Unknown error occurred", ex);
//        return buildErrorDTO(ex, HttpStatus.INTERNAL_SERVER_ERROR, request);
//    }
//
//    @ExceptionHandler(Exception.class)
//    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
//    public ResponseEntity<Object> handleAllUncaughtExceptions(Exception ex, WebRequest request) {
//        log.error("Unknown error occurred", ex);
//        return buildErrorDTO(ex, HttpStatus.INTERNAL_SERVER_ERROR, request);
//    }
//
//    @Override
//    public ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers, HttpStatus status, WebRequest request) {
//        return buildErrorDTO(ex,status,request);
//    }
//
//    private ResponseEntity<Object> buildErrorDTO(Exception ex, HttpStatus status, WebRequest request) {
//        ErrorDTO errorDTO = new ErrorDTO(status, ex.getMessage());
//        if (printStackTrace) {
//            errorDTO.setStackTrace(ExceptionUtils.getStackTrace(ex));
//        }
//        return ResponseEntity.status(status).body(errorDTO);
//    }
//
//}
