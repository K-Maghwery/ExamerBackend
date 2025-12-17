package com.online_exam.examer.question.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor

public class CategoryDto {
    private String categoryName;
    private Long num_easy;
    private Long num_medium;
    private Long num_hard;
    private Long num_totalQuestions;
}
