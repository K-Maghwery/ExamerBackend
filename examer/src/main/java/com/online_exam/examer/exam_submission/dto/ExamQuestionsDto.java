package com.online_exam.examer.exam_submission.dto;

import com.online_exam.examer.question.QuestionOptionEntity;
import com.online_exam.examer.question.enums.QuestionType;
import com.online_exam.examer.question.dto.OptionDto;
import lombok.Data;

import java.io.Serializable;
import java.util.List;

@Data
public class ExamQuestionsDto implements Serializable {

    private Long questionId;

    private String questionContent;

    private QuestionType questionType;

    // Null for WRITTEN
//    private List<OptionDto> options;
    private List<String> options;

    private List<Integer> correctOptionIndexes;
}
