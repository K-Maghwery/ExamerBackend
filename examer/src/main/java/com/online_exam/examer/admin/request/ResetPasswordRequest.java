package com.online_exam.examer.admin.request;

import lombok.Data;

@Data
public class ResetPasswordRequest {
    private String adminEmail;
    private String otpCode;

}
