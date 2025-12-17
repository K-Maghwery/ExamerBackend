package com.online_exam.examer.admin.request;

import lombok.Data;

@Data
public class UpdateForgetPasswordRequest {
    private String AdminEmail;
    private String newPassword;
}
