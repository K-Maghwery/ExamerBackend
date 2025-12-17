package com.online_exam.examer.user.request;

import lombok.Data;

@Data
public class UpdateUserRequest {
    private String userName;
    private String phone;
    private String email;
}
