package com.online_exam.examer.exam;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;


import java.util.List;

public interface ExamRepository extends JpaRepository<ExamEntity, Long> {


    Page<ExamEntity>findAllByAdmin_AdminId(Long adminId,Pageable pageable);
    List<ExamEntity>findAllByAdmin_AdminId(Long adminId);

    @Query("SELECT (e.easy + e.medium + e.hard) FROM ExamEntity e WHERE e.examId = :examId")
    Long countTotalQuestionsByExamId(@Param("examId") Long examId);


    /****************** Not Used ******************/
    //boolean existsByExamTitle(String examTitle);

   //Page<ExamEntity> findAllByExamTitle(String examTitle, Pageable pageable);

    //List<ExamEntity>findAllByAdmin_AdminUserName(String adminUserName);
}
