package com.online_exam.examer.admin;

import com.online_exam.examer.admin.request.*;
import com.online_exam.examer.mapper.PageDto;
import org.springframework.data.domain.Pageable;

public interface IAdminService {

   /****************** For SuperAdmin Only ****************/
   SuperAdminResponse addSuperAdmin(AddAdminRequest addAdminRequest);

    PageDto<AdminDto> deleteAdminById(Long adminId,Pageable pageable);

    PageDto<AdminDto> hardDeleteAdmin(Long adminId,Pageable pageable);

    PageDto<AdminDto> getAdminsByRole(String role, Pageable pageable);
    PageDto<AdminDto> getDeletedAdmins(String role, Pageable pageable);
    PageDto<AdminDto> recoverAdmin(RecoverAdminRequest recoverAdminRequest, Pageable pageable);
    /****************** SuperAdmin Ends ********************/



 /************** For SuperAdmin And other Admins ********/

    void addAdmin(AddAdminRequest addAdminRequest);

    void updateAdminPasswordById(Long adminId, UpdateAdminPasswordRequest updateAdminPasswordRequest);


    AdminDto updateAdminInfoById(Long adminId, UpdateAdminInfoRequest updateAdminInfoRequest);

    AdminDto getAdminById(Long adminId);

    boolean isAdminDeleted(String adminUsername);


    /**********************Not Used**********************/
    //List<AdminEntity> getAllAdmins();// leave it now we will check it later
    //AdminDto updateAdminPasswordById(Long adminId, UpdateAdminPasswordRequest updateAdminPasswordRequest);
    //PageDto<AdminDto> updateAdminInfoBySuperAdminById(Long adminId, UpdateAdminInfoRequest updateAdminInfoRequest, Pageable pageable);


}
