package com.online_exam.examer.question.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CategoryWithTotalQuestionDto {

    private String categoryName;
    private Long num_totalQuestions;


}
