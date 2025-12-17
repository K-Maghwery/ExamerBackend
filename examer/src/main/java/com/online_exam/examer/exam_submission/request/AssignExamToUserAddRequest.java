package com.online_exam.examer.exam_submission.request;

import lombok.Data;

@Data
public class AssignExamToUserAddRequest {

    private Long userId;
    private Long examId;

}
