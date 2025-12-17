package com.online_exam.examer.admin.request;

import lombok.Data;

@Data
public class UpdateAdminInfoRequest {

    private String adminUserName;
    private String email;
    private String phone;

}
