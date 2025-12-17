package com.online_exam.examer.admin.request;

import lombok.Data;

@Data
public class AddAdminRequest {
   // private Long adminId;
//   @NotBlank(message = "Admin username is required.")
//   @Pattern(regexp = "^[a-zA-Z_]{1,20}$", message = "Admin username must be 1-20 letters or underscores only.")
    private String adminUserName;

// @NotEmpty(message = "Phone number cannot be empty")
// @Pattern(regexp = "^(012|011|015|010)\\d{8}$", message = "Phone number must start with 010, 011, 012, or 015 and be followed by 8 digits")
    private String phone;

//    @NotEmpty(message = "Email cannot be empty")
//    @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Email must be valid")
//   @Email(message = "Invalid email format")
    private String email;
//    private String password;
    //private String role;//we send it as static remove it to add superadmin

}
