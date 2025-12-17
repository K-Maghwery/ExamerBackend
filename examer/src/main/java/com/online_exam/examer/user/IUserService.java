package com.online_exam.examer.user;

import com.online_exam.examer.mapper.PageDto;
import com.online_exam.examer.user.request.AddUserRequest;
import com.online_exam.examer.user.request.RecoverUserRequest;
import com.online_exam.examer.user.request.SoftDeleteRequest;
import com.online_exam.examer.user.request.UpdateUserRequest;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface IUserService {

    void addUser(AddUserRequest addUserRequest);
    PageDto<UserDto> softDeleteUser(SoftDeleteRequest softDeleteRequest, Pageable pageable);
    PageDto<UserDto> updateUser(Long userId, UpdateUserRequest updateUserRequest, Pageable pageable);
    UserDto getUserById(Long UserId);

    PageDto<UserDto> findByAdminId(Long adminId,Pageable pageable) ;
    PageDto<UserDto> findUsersByAdminIdAndStatusFalse(Long examId,Long adminId,Pageable pageable) ;
    List<UserDto> findUsersByAdminIdAndNotAssigned(Long examId,Long adminId) ;
    PageDto<UserDto> getDeletedUsersByAdminId(Long adminId, Pageable pageable);
    PageDto<UserDto> hardDeleteByUserId(Long UserId, Pageable pageable);
    PageDto<UserDto> recoverUser(RecoverUserRequest recoverUserRequest, Pageable pageable);

    /****************** Not Used ******************/

    //PageDto<UserDto> getAllUsers(Pageable pageable);
    //List<UserDto> findByAdminAdminUserName(String adminUsername) ;
}

