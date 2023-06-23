package com.pyrosandro.auth.dto.response;

//TODO - Move ErrorDTO to a common package. Learn how to publish a package so that you can import it as dependency.

import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpStatus;

import java.util.ArrayList;
import java.util.Objects;

@Data
@RequiredArgsConstructor
public class ErrorDTO {

    private final HttpStatus httpStatus;
    private final String message;
    private String stackTrace;
    //TODO - add timestamp field
    //TODO - add private List<ValidationError> validationErrors;


//    @Getter
//    @Setter
//    @RequiredArgsConstructor
//    private static class ValidationError {
//        private final String field;
//        private final String message;
//    }
//
//    public void addValidationError(String field, String message){
//        if(Objects.isNull(validationErrors)){
//            validationErrors = new ArrayList<>();
//        }
//        validationErrors.add(new ValidationError(field, message));
//    }

}
