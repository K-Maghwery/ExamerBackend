package com.online_exam.examer.exam_submission.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserExamDetailsDto implements Serializable {
    private Long userId;
    private String userName;
    private String examName;
    private int score;
}
