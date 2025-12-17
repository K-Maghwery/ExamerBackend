package com.online_exam.examer.exam;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.sql.Timestamp;

@Data

public class ExamDto implements Serializable {

    private Long examId;
    private String examTitle;
    private String examDescription;
    private int examDuration;
    private int easy;
    private int medium;
    private int hard;
    private Timestamp createdDate;
    private Long adminId;
}
