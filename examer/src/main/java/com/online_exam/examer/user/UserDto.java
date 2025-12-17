package com.online_exam.examer.user;


import lombok.Data;

import java.io.Serializable;

@Data
public class UserDto implements Serializable {
    private Long userId;
    private String userName;
    private String phone;
    private String email;
//    private List<ExamSubmissionDto> examSubmissions; // Collection of ExamSubmissionDto
}
