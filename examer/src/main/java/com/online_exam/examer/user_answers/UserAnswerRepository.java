package com.online_exam.examer.user_answers;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserAnswerRepository extends JpaRepository<UserAnswerEntity, Integer> {

    List<UserAnswerEntity> findByExamSubmission_ExamSubmissionId(Long examSubmissionId);
}

