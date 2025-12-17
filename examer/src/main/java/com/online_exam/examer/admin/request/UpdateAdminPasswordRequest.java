package com.online_exam.examer.admin.request;

import lombok.Data;

@Data
public class UpdateAdminPasswordRequest {

    //private Long adminId;

    private String oldPassword;
    private String newPassword;
    //private String role;//we send it as static remove it to add superadmin
}
