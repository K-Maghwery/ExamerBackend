package com.online_exam.examer.question.request;

import com.online_exam.examer.question.enums.QuestionType;
import lombok.Data;

import java.util.List;

@Data
public class UpdateQuestionRequest {
    private String questionContent;

    private String difficulty;

    private String category;

    private QuestionType questionType;

    private List<String> options;

    private List<Integer> correctOptionIndexes;
}
