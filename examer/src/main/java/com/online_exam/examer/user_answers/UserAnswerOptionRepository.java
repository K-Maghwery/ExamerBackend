package com.online_exam.examer.user_answers;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserAnswerOptionRepository
        extends JpaRepository<UserAnswerOptionEntity, UserAnswerOptionId> {
}

