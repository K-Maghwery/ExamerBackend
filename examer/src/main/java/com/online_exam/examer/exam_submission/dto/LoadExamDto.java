package com.online_exam.examer.exam_submission.dto;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

@Data
public class LoadExamDto  implements Serializable {

    private int examDuration;
    private String userName;
    private String examTitle;
    private List <ExamQuestionsDto> examQuestions;

}
