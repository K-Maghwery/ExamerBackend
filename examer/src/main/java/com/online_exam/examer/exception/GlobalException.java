package com.online_exam.examer.exception;

import com.online_exam.examer.response.GeneralResponse;
import jakarta.validation.ConstraintViolationException;
import org.eclipse.angus.mail.util.MailConnectException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class GlobalException {

    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ResponseEntity<GeneralResponse> resourceNotFound(ResourceNotFoundException e) {
        return new ResponseEntity<>(new GeneralResponse(e.getMessage()), HttpStatus.NOT_FOUND);


    }

    @ExceptionHandler(AlreadyExsistsException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ResponseEntity<GeneralResponse> alreadyExistsException(AlreadyExsistsException e) {
        return new ResponseEntity<>(new GeneralResponse(e.getMessage()), HttpStatus.CONFLICT);
    }

    @ExceptionHandler(PasswordNotMatchedException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ResponseEntity<GeneralResponse> passwordNotMatchedException(PasswordNotMatchedException e) {
        return new ResponseEntity<>(new GeneralResponse(e.getMessage()), HttpStatus.CONFLICT);
    }

    @ExceptionHandler(CurrentPasswordMatchNewPassword.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ResponseEntity<GeneralResponse> currentPasswordMatchNewPassword(CurrentPasswordMatchNewPassword e) {
        return new ResponseEntity<>(new GeneralResponse(e.getMessage()), HttpStatus.CONFLICT);
    }

    @ExceptionHandler(InvalidOtpException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<GeneralResponse> invalidOtpException(InvalidOtpException e) {
        return new ResponseEntity<>(new GeneralResponse(e.getMessage()), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseEntity<GeneralResponse> handleAuthenticationException() {
        return new ResponseEntity<>(new GeneralResponse("username or password incorrect"), HttpStatus.UNAUTHORIZED);
    }


    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GeneralResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        // Extract only the error messages from all field errors
        String errorMessage = ex.getBindingResult().getAllErrors().get(0).getDefaultMessage();
        return new ResponseEntity<>(new GeneralResponse(errorMessage),HttpStatus.BAD_REQUEST) ;
//        return new ResponseEntity<>(errorMessage,HttpStatus.BAD_REQUEST) ; // and  ResponseEntity<String>
    }

    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GeneralResponse> handleConstraintViolationException(ConstraintViolationException ex) {
        // Extract the first validation error message
//      String errorMessage = ex.getBindingResult().getAllErrors().get(0).getDefaultMessage();
        String errorMessage = ex.getConstraintViolations()
                .stream()
                .findFirst()
                .map(violation -> violation.getMessage())
                .orElse("Validation error occurred.");
        return new ResponseEntity<>(new GeneralResponse(errorMessage),HttpStatus.BAD_REQUEST) ;
    }
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<GeneralResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
//        return ResponseEntity
//                .status(HttpStatus.BAD_REQUEST)
//                .body(new ApiResponse(ex.getMessage(), null));
        return new ResponseEntity<>(new GeneralResponse(ex.getMessage()),HttpStatus.BAD_REQUEST) ;

    }


    @ExceptionHandler(SendEmailFailedException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ResponseEntity<GeneralResponse> failedToSendEmail(SendEmailFailedException e) {
        return new ResponseEntity<>(new GeneralResponse(e.getMessage()), HttpStatus.SERVICE_UNAVAILABLE);


    }

    @ExceptionHandler(MailConnectException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ResponseEntity<GeneralResponse> failedToSendEmail() {
        return new ResponseEntity<>(new GeneralResponse("Failed To Send Email Check Your Internet Connection"), HttpStatus.SERVICE_UNAVAILABLE);


    }
    @ExceptionHandler(GeminiApiException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GeneralResponse> failedToFetchData() {
        return new ResponseEntity<>(new GeneralResponse("Can't Fetch Data Check Your Input Data And Try Again"), HttpStatus.BAD_REQUEST);


    }



}
