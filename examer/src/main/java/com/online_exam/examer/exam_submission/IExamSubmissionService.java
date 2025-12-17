package com.online_exam.examer.exam_submission;

import com.online_exam.examer.exam_submission.dto.LoadExamDto;
import com.online_exam.examer.exam_submission.dto.UserExamDetailsDto;
import com.online_exam.examer.exam_submission.request.AssignExamToUserAddRequest;
import com.online_exam.examer.exam_submission.request.AssignExamToUserUpdateRequest;
import com.online_exam.examer.exam_submission.request.ResetExamToUserRequest;
import com.online_exam.examer.mapper.PageDto;
import com.online_exam.examer.user.UserDto;
import org.springframework.data.domain.Pageable;

public interface IExamSubmissionService {

    PageDto<UserDto> assignExamToUser(AssignExamToUserAddRequest assignExamToUserAddRequest, Pageable pageable);

    void updateExamToUser(String encryptedExamSubmissionId, AssignExamToUserUpdateRequest assignExamToUserUpdateRequest);//leave it till the end (note :examSubmissionId will be sent by front as requestparam(in controller), and examSubmission will be sent by front as request body(incontroller))

    void resetExamToUser(ResetExamToUserRequest resetExamToUserRequest);

    PageDto<UserExamDetailsDto> getUsersForExamAndAdmin(Long examId, Long adminId, Pageable pageable);

    LoadExamDto getExamQuestionsByExamSubmissionId(String encryptedExamSubmissionId);

}
