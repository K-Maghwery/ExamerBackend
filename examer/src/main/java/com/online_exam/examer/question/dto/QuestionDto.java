package com.online_exam.examer.question.dto;

import com.online_exam.examer.question.enums.QuestionType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class QuestionDto {
    private long questionId;
    private String questionContent;
    private String difficulty;
    private String category;
    private QuestionType questionType;

    // Null for WRITTEN
    private List<String> options;
    //private List<OptionDto> options;

    // Empty for WRITTEN
    private List<Integer> correctOptionIndexes;
//    private AdminEntity admin;
//    private List<ExamEntity> exams;
}
