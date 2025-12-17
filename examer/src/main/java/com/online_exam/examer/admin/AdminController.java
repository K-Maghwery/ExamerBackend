package com.online_exam.examer.admin;
import com.online_exam.examer.admin.request.*;
import com.online_exam.examer.response.ApiResponse;

import com.online_exam.examer.response.GeneralResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.core.env.Environment;

@RestController
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;
    private final Environment environment;


    @PostMapping(path = "addAdmin")
    public ResponseEntity<GeneralResponse> addAdmin(@RequestBody @Validated AddAdminRequest addAdminRequest) {
        adminService.addAdmin(addAdminRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(new GeneralResponse("Admin added successfully"));
    }

    @PostMapping(path = "addSuperAdmin")
    public ResponseEntity<ApiResponse> addSuperAdmin(
            @RequestHeader("X-Setup-Token") String setupToken,
            @RequestBody @Validated AddAdminRequest addAdminRequest) {

        String expectedToken = environment.getProperty("setup.token");

        if (!setupToken.equals(expectedToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse("Unauthorized: Invalid token", null));
        }

        SuperAdminResponse response = adminService.addSuperAdmin(addAdminRequest);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ApiResponse("Super Admin added successfully", response));
    }


    @GetMapping("/getAdminsByRole/{role}")
    public ResponseEntity<ApiResponse> getAdminsByRole(@PathVariable String role,@PageableDefault(size = 5) Pageable pageable) {

        return ResponseEntity.status(HttpStatus.OK)
                .body(new ApiResponse("Success to get admins with Role: " + role,  adminService.getAdminsByRole(role, pageable)));
    }
    @GetMapping("/getDeletedAdmins/{role}")
    public ResponseEntity<ApiResponse> getDeletedAdmins(@PathVariable String role,@PageableDefault(size = 5) Pageable pageable) {

        return ResponseEntity.status(HttpStatus.OK)
                .body(new ApiResponse("Success to get admins with Role: " + role,  adminService.getDeletedAdmins(role, pageable)));
    }

    @DeleteMapping(path ="hardDeleteAdmin/{adminId}")
    public ResponseEntity<ApiResponse> hardDeleteAdmin(@PathVariable Long adminId,@PageableDefault(size = 5) Pageable pageable) {
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Admin Deleted Successfully", adminService.hardDeleteAdmin(adminId, pageable)));
    }


    @PutMapping(path ="recoverAdmin")
    public ResponseEntity<ApiResponse> recoverAdmin(@RequestBody RecoverAdminRequest recoverAdminRequest, @PageableDefault(size = 5) Pageable pageable) {
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Admin Recovered Successfully", adminService.recoverAdmin(recoverAdminRequest, pageable)));
    }



    @GetMapping(path = "getAdminById/{adminId}")
    public ResponseEntity<ApiResponse> getAdminById(@PathVariable Long adminId) {

        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Admin Founded Successfully", adminService.getAdminById(adminId)));

    }
    @PutMapping(path ="deleteAdminById")
    public ResponseEntity<ApiResponse> deleteAdminById(@RequestBody SoftDeleteRequest softDeleteRequest, @PageableDefault(size = 5) Pageable pageable) {
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Admin Deleted Successfully", adminService.deleteAdminById(softDeleteRequest.getAdminId(), pageable)));
    }

    @PutMapping(path = "updateAdminPasswordById/{adminId}")
    public ResponseEntity<GeneralResponse> updateAdminPassword(@PathVariable Long adminId, @RequestBody UpdateAdminPasswordRequest updateAdminPasswordRequest) {

        adminService.updateAdminPasswordById(adminId, updateAdminPasswordRequest);
        return ResponseEntity.status(HttpStatus.OK).body(new GeneralResponse("Password Updated Successfully"));

    }


    @PutMapping(path = "updateAdminInfoById/{adminId}")
    public ResponseEntity<ApiResponse> updateAdminInfo(@PathVariable Long adminId, @RequestBody  @Validated UpdateAdminInfoRequest updateAdminInfoRequest) {

        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Info Updated Successfully", adminService.updateAdminInfoById(adminId, updateAdminInfoRequest)));

    }


/*********************** Not Used End Points *****************************/

//    @PutMapping(path = "updateAdminInfoBySuperAdminById/{adminId}")
//    public ResponseEntity<ApiResponse> updateAdminInfoBySuperAdmin(@PathVariable Long adminId, @RequestBody UpdateAdminInfoRequest updateAdminInfoRequest,@PageableDefault(size = 5) Pageable pageable) {
//
//        return ResponseEntity.status(HttpStatus.OK).
//                body(new ApiResponse("Info Updated Successfully", adminService.updateAdminInfoBySuperAdminById(adminId, updateAdminInfoRequest,pageable)));
//
//    }


}
