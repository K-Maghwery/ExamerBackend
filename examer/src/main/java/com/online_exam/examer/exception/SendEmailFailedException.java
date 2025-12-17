package com.online_exam.examer.exception;

public class SendEmailFailedException extends RuntimeException {
    public SendEmailFailedException(String message) {
        super(message);
    }
}
