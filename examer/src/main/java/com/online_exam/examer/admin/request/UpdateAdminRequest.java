package com.online_exam.examer.admin.request;

import lombok.Data;

@Data
public class UpdateAdminRequest {

    //private Long adminId;
    private String adminUserName;
    private String phone;
    private String email;
    private String password;
    //private String role;//we send it as static remove it to add superadmin
}
