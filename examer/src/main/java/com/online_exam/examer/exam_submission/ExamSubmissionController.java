package com.online_exam.examer.exam_submission;


import com.online_exam.examer.exam_submission.request.AssignExamToUserAddRequest;
import com.online_exam.examer.exam_submission.request.AssignExamToUserUpdateRequest;
import com.online_exam.examer.exam_submission.request.ResetExamToUserRequest;
import com.online_exam.examer.response.ApiResponse;
import com.online_exam.examer.response.GeneralResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class ExamSubmissionController {

    private final ExamSubmissionService examSubmissionService;


    @PostMapping(path = "assign")
    public ResponseEntity<ApiResponse> assignExamToUser(@RequestBody @Validated AssignExamToUserAddRequest assignExamToUserAddRequest, @PageableDefault(size = 5) Pageable pageable) {


        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("Exam Assigned Successfully", examSubmissionService.assignExamToUser(assignExamToUserAddRequest, pageable)));


    }

    @PutMapping(path = "assignupdate")
    public ResponseEntity<GeneralResponse> updateAssignExamToUser(@RequestParam @Validated String id, @RequestBody AssignExamToUserUpdateRequest assignExamToUserUpdateRequest) {

        examSubmissionService.updateExamToUser(id, assignExamToUserUpdateRequest);
            return ResponseEntity.status(HttpStatus.OK).body(new GeneralResponse("Updated Successfully"));


    }
    @GetMapping(path = "examQuestions")
    public ResponseEntity<ApiResponse> getExamQuestions(@RequestParam String id) {


            return ResponseEntity.status(HttpStatus.OK).
                    body(new ApiResponse("Get Questions Successfully",examSubmissionService.getExamQuestionsByExamSubmissionId(id)));


    }
    @GetMapping("/getUsersForExamAndAdmin/{examId}/{adminId}")
    public ResponseEntity<ApiResponse> getUsersForExamAndAdmin(
            @PathVariable Long examId,
            @PathVariable Long adminId,
            @PageableDefault(size = 5) Pageable pageable) {
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse(" All score retrieve  successfully", examSubmissionService.getUsersForExamAndAdmin(examId, adminId,pageable)));
    }

    @PutMapping(path = "resetUserExam")
    public ResponseEntity<GeneralResponse> updateUserExam(@RequestBody ResetExamToUserRequest resetExamToUserRequest) {

        examSubmissionService.resetExamToUser(resetExamToUserRequest);
        return ResponseEntity.status(HttpStatus.OK).body(new GeneralResponse("Reset Successfully"));


    }
}
