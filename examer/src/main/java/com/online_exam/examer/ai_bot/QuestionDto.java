package com.online_exam.examer.ai_bot;

import lombok.Data;

@Data
public class QuestionDto {

    private String questionContent;
    private String difficulty;
    private String category;
    private String correctAnswer;
    private String option1;
    private String option2;
    private String option3;
    private String option4;
}
