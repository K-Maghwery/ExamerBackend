package com.online_exam.examer.user;

import com.online_exam.examer.response.ApiResponse;
import com.online_exam.examer.response.GeneralResponse;
import com.online_exam.examer.user.request.AddUserRequest;
import com.online_exam.examer.user.request.RecoverUserRequest;
import com.online_exam.examer.user.request.SoftDeleteRequest;
import com.online_exam.examer.user.request.UpdateUserRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    @PostMapping("addUser")
    public ResponseEntity<GeneralResponse> addUser(@RequestBody  @Validated AddUserRequest addUserRequest) {
        userService.addUser(addUserRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(new GeneralResponse("User Successfully Added"));

    }
    @PutMapping("deleteUser")
    public ResponseEntity<ApiResponse> softDeleteUser(@RequestBody SoftDeleteRequest softDeleteRequest, @PageableDefault(size = 5) Pageable pageable) {
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("User Deleted Successfully", userService.softDeleteUser(softDeleteRequest, pageable)));
    }
    @PutMapping("updateUser/{userId}")
    public ResponseEntity<ApiResponse> updateUser(@RequestBody @Validated UpdateUserRequest updateUserRequest, @PathVariable Long userId, @PageableDefault(size = 5) Pageable pageable) {
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("User Updated Successfully :) ", userService.updateUser(userId, updateUserRequest, pageable)));

    }
    @GetMapping("getUser/{userId}")
    public ResponseEntity<ApiResponse>getUserById(@PathVariable Long userId) {
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("User Founded Successfully",userService.getUserById(userId)));

    }


    @GetMapping("usersOfAdmin/{adminId}")
    public ResponseEntity<ApiResponse> findByAdminId(@PathVariable Long adminId,@PageableDefault(size = 5) Pageable pageable){
        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("Success to get Users of admin : ", userService.findByAdminId(adminId,pageable)));
    }

    @GetMapping("usersOfAdminAndStatus/{examId}/{adminId}")
    public ResponseEntity<ApiResponse> findByAdminIdAndStatus(@PathVariable Long examId,@PathVariable Long adminId,@PageableDefault(size = 5) Pageable pageable){
        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("Success to get Users of admin : ", userService.findUsersByAdminIdAndStatusFalse(examId,adminId,pageable)));
    }
    @GetMapping("usersOfAdminAndNotAssigned/{examId}/{adminId}")
    public ResponseEntity<ApiResponse> findByAdminIdAndNotAssigned(@PathVariable Long examId,@PathVariable Long adminId){
        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("Success to get Users of admin : ", userService.findUsersByAdminIdAndNotAssigned(examId,adminId)));
    }
    @GetMapping("getDeletedUsersByAdminId/{adminId}")
    public ResponseEntity<ApiResponse> getDeletedUsersByAdminId(@PathVariable Long adminId,@PageableDefault(size = 5) Pageable pageable){
        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("Success to get Deleted Users : ", userService.getDeletedUsersByAdminId(adminId,pageable)));
    }
    @DeleteMapping("hardDeleteByUserId/{userId}")
    public ResponseEntity<ApiResponse> hardDeleteByUserId(@PathVariable Long userId,@PageableDefault(size = 5) Pageable pageable){
        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("User Deleted Successfully", userService.hardDeleteByUserId(userId,pageable)));
    }
    @PutMapping("recoverUser")
    public ResponseEntity<ApiResponse> recover(@RequestBody @Validated RecoverUserRequest recoverUserRequest, @PageableDefault(size = 5) Pageable pageable){
        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("User recovered Successfully", userService.recoverUser(recoverUserRequest,pageable)));
    }

    /******************** Not Used End Points ********************/

//    @GetMapping("allUsers")
//    public ResponseEntity<ApiResponse> getAllUsers(@PageableDefault(size = 5) Pageable pageable) {
//        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("Success to get All Users : ", userService.getAllUsers(pageable)));
//    }
//
//
//    @GetMapping("userOfAdmin/{adminUsername}")
//    public ResponseEntity<ApiResponse> findByAdminAdminUserName(@PathVariable String adminUsername){
//        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("Success to get Users of admin : ", userService.findByAdminAdminUserName(adminUsername)));
//    }

}
