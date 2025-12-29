package com.online_exam.examer.user_answers;

import com.online_exam.examer.exam_submission.ExamSubmissionEntity;
import com.online_exam.examer.user_answers.dto.UserAnswerViewDto;
import com.online_exam.examer.user_answers.request.UserAnswerSubmitRequest;

import java.util.List;

public interface IUserAnswerService {
    void submitAnswer(UserAnswerSubmitRequest request);

    List<UserAnswerViewDto> getAnswersBySubmission(Long examSubmissionId);

    int calculateScore(Long examSubmissionId);
}
