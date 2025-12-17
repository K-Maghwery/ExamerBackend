package com.online_exam.examer.user;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    boolean existsByEmail(String email);


    @Query("SELECT u FROM UserEntity u " +
            "JOIN u.examSubmission es " +
            "WHERE es.exam.examId = :examId AND u.admin.adminId = :adminId AND u.isDeleted = false AND es.status = false")
    Page<UserEntity> findUsersByExamIdAndSubmissionStatus(@Param("examId") Long examId,@Param("adminId") Long adminId , Pageable pageable);

    @Query("SELECT u FROM UserEntity u " +
            "LEFT JOIN u.examSubmission es ON es.exam.examId = :examId " +
            "WHERE u.admin.adminId = :adminId " +
            "AND (es IS NULL OR es.exam.examId != :examId) " +
            "AND u.isDeleted = false")
    List<UserEntity> findUsersByAdminIdWithoutExamSubmission(@Param("examId") Long examId, @Param("adminId") Long adminId);

    Page<UserEntity> findByAdminAdminIdAndIsDeletedFalse(Long adminId, Pageable pageable);
    Page<UserEntity> findByAdminAdminIdAndIsDeletedTrue(Long adminId, Pageable pageable);
    boolean existsByUserIdAndIsDeletedFalse(Long userId);

    boolean existsByUserNameAndUserIdNot(String userName, Long userId);
    boolean existsByEmailAndUserIdNot(String email, Long userId);
    boolean existsByAdmin_AdminIdAndUserName(Long adminId, String userName);
    boolean existsByAdmin_AdminIdAndEmail(Long adminId, String email);
    boolean existsByAdmin_AdminIdAndUserNameAndIsDeletedTrue(Long adminId, String userName);
    boolean existsByAdmin_AdminIdAndEmailAndIsDeletedTrue(Long adminId, String email);
    boolean existsByAdmin_AdminIdAndUserNameAndIsDeletedFalse(Long adminId, String userName);
    boolean existsByAdmin_AdminIdAndEmailAndIsDeletedFalse(Long adminId, String email);

    /****************** Not Used ******************/

    //boolean existsByUser_UserIdAndExam_ExamId(Long userId, Long examId);
    //Page<UserEntity> findByIsDeletedFalse(Pageable pageable);
    //List<UserEntity> findByAdminAdminUserNameAndIsDeletedFalse(String adminUsername);
    //boolean existsByUserNameAndIsDeletedTrue(String userName);
    //boolean existsByEmailAndIsDeletedTrue(String email);

    //@Query("SELECT u FROM UserEntity u " +
    //"LEFT JOIN u.examSubmission es ON es.exam.examId = :examId " +
    //"WHERE u.admin.adminId = :adminId AND (es IS NULL OR es.exam.examId != :examId)")
    //List<UserEntity> findUsersByAdminIdWithoutExamSubmission(@Param("examId") Long adminId, @Param("adminId") Long examId);

    //List<UserEntity> findByAdminAdminUserName(String adminUserName);
    //List<UserEntity> findByAdminAdminId(Long adminId);
    //Page<UserEntity> findByAdminAdminId(Long adminId, Pageable pageable);

    //@Query("SELECT u FROM UserEntity u " +
    //"JOIN u.examSubmission es " +
    //"WHERE es.exam.examId = :examId AND u.admin.adminId = :adminId AND es.status = false")
    //List<UserEntity> findUsersByExamIdAndSubmissionStatus(@Param("examId") Long examId,@Param("adminId") Long adminId);
    //boolean existsByUserName(String userName);
}