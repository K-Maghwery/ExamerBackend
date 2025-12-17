package com.online_exam.examer.exam;


import lombok.Data;

import java.io.Serializable;

@Data
public class ExamDropListDto implements Serializable {

    private Long examId;
    private String examTitle;
    private Long totalQuestions;
}
