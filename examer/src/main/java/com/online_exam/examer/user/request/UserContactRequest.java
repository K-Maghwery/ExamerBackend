package com.online_exam.examer.user.request;

import lombok.Data;

@Data
public class UserContactRequest {
//this request made for contact page for allowing user to contact with support team
    private String userEmail;
    private String subject;
    private String userMessage;

}
