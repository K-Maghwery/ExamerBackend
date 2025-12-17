package com.online_exam.examer.exception;

public class CurrentPasswordMatchNewPassword extends RuntimeException {
    public CurrentPasswordMatchNewPassword(String message) {
        super(message);
    }
}
