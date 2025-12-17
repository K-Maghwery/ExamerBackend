package com.online_exam.examer.admin;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface AdminRepository extends JpaRepository<AdminEntity, Long> {

    Page<AdminEntity> findAllByRoleAndIsDeletedFalse(String role, Pageable pageable);
    Page<AdminEntity> findAllByRoleAndIsDeletedTrue(String role, Pageable pageable);
    boolean existsByRole(String role);
    boolean existsByAdminUserName(String adminUserName);
    boolean existsByEmail(String email);


    // Check if admin exists by username and deleted state

    boolean existsByAdminUserNameAndIsDeletedTrue(String adminUserName);

    boolean existsByEmailAndIsDeletedTrue(String adminUserName);

    boolean existsByAdminUserNameAndIsDeletedFalse(String adminUserName);

    boolean existsByEmailAndIsDeletedFalse(String adminUserName);

    AdminEntity findByAdminUserName(String username);

    AdminEntity findByEmail(String adminEmail);

    /****************** Not Used ******************/

    //@Query("SELECT COUNT(a) > 0 FROM AdminEntity a WHERE a.adminUserName = :adminUserName AND a.isDeleted = true")
    //boolean existsByAdminUserNameAndIsDeletedTrue(String adminUserName);
    //Page<AdminEntity> findAllByRole(String role, Pageable pageable);

}
