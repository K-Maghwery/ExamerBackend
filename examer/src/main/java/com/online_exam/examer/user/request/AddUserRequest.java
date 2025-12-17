package com.online_exam.examer.user.request;

import lombok.Data;

@Data
public class AddUserRequest {
//    @NotBlank(message = "Username is required.")
//    @Pattern(regexp = "^[a-zA-Z_]{1,20}$", message = "Username must be 1-20 letters or underscores only.")
    private String userName;
//    @NotEmpty(message = "Email cannot be empty")
//    @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Email must be valid")
    private String email;
//    @NotEmpty(message = "Phone number cannot be empty")
//    @Pattern(regexp = "^(012|011|015|010)\\d{8}$", message = "Phone number must start with 010, 011, 012, or 015 and be followed by 8 digits")
    private String phone;
    private Long adminId;
}
