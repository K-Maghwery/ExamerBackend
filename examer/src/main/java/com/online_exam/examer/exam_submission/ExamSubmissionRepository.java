package com.online_exam.examer.exam_submission;

import com.online_exam.examer.exam_submission.dto.UserExamDetailsDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ExamSubmissionRepository extends JpaRepository<ExamSubmissionEntity,Long> {


    @Query("SELECT new com.online_exam.examer.exam_submission.dto.UserExamDetailsDto(u.userId,u.userName, e.examTitle, es.score) " +
            "FROM ExamSubmissionEntity es " +
            "JOIN es.user u " +
            "JOIN es.exam e " +
            "JOIN e.admin a " +
            "WHERE e.examId = :examId " +
            "AND a.adminId = :adminId " +
            "AND es.status = true " +
            "AND es.isDeleted = false ")
    Page<UserExamDetailsDto> findUserExamDetailsByExamAndAdmin(@Param("examId") Long examId,
                                                               @Param("adminId") Long adminId,
                                                               Pageable pageable);


    boolean existsByUser_UserIdAndExam_ExamId(Long userId, Long examId);

    ExamSubmissionEntity findByUser_UserIdAndExam_ExamId(Long userId, Long examId);
}
