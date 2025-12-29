package com.online_exam.examer.user_answers.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import java.util.List;



@Data
public class UserAnswerSubmitRequest {

    @NotNull
    private Long examSubmissionId;

    // List of answers for all questions in the exam
    @NotEmpty
    private List<QuestionAnswer> answers;

    @Data
    public static class QuestionAnswer {

        @NotNull
        private Long questionId;

        // For written
        private String writtenAnswer;

        // For MCQ / multiple choice
        private List<Long> selectedOptionIds;
    }
}
