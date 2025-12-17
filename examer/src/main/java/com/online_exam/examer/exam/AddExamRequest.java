package com.online_exam.examer.exam;


import lombok.Data;

@Data
public class AddExamRequest {

//    private Long examId;
    private String categoryName;
    private String examTitle;
    private String examDescription;
    private int examDuration;
    private int easy;
    private int medium;
    private int hard;
    private Long adminId;
}
