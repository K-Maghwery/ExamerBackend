package com.online_exam.examer.admin.request;

import lombok.Data;

@Data
public class LoginAdminRequest {

    private String adminUserName;
    private String password;
}
