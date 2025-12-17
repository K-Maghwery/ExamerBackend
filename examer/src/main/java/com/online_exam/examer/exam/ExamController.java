package com.online_exam.examer.exam;

import com.online_exam.examer.response.ApiResponse;
import com.online_exam.examer.response.GeneralResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import org.springframework.data.domain.Pageable;


@RestController
@RequiredArgsConstructor
public class ExamController {

    private final ExamService examService;

    @PostMapping(path = "addExam")
    public ResponseEntity<GeneralResponse> addExam(@RequestBody @Validated AddExamRequest addExamRequest) {
            examService.addExam(addExamRequest);
            return ResponseEntity.status(HttpStatus.OK).body(new GeneralResponse("Exam added successfully"));

    }


    @DeleteMapping(path = "deleteExamById/{examId}")
    public ResponseEntity<ApiResponse> deleteExamById(@PathVariable Long examId,@PageableDefault(size = 5) Pageable pageable) {

        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Exam deleted successfully", examService.deleteExamById(examId, pageable)));

    }


    @GetMapping(path = "getAllExamsByAdminId/{adminId}")
    public ResponseEntity<ApiResponse> getAllExamsByAdminId(@PathVariable Long adminId,@PageableDefault(size = 4) Pageable pageable) {

        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Exams found", examService.getAllExamsByAdminId(adminId, pageable)));
    }

    @GetMapping(path = "getAllExamsList/{adminId}")
    public ResponseEntity<ApiResponse> getAllExamsByAdminId(@PathVariable Long adminId) {

        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Exams found", examService.getAllExamsTitle(adminId)));
    }


    /******************* Not Used End Points *******************/

//    @GetMapping(path = "getExamByTitle/{examTitle}")
//    public ResponseEntity<ApiResponse> getExamsByExamTitle(@PathVariable String examTitle,@PageableDefault(size = 5) Pageable pageable) {
//
//        return ResponseEntity.status(HttpStatus.OK).
//                body(new ApiResponse("Exams found", examService.getExamsByExamTitle(examTitle, pageable)));
//    }

//    @GetMapping(path = "getAllExamsByAdminUsername/{username}")
//    public ResponseEntity<ApiResponse> getAllExamsByAdminUsername(@PathVariable String username) {
//
//        return ResponseEntity.status(HttpStatus.OK).
//                body(new ApiResponse("Exams found", examService.getAllExamsByAdminUsername(username)));
//    }

//    @PostMapping("getQuestionsForExam")
//    public ResponseEntity<ApiResponse> getQuestionsForExam(@RequestBody AddExamRequest request) {
//        // Validate the request data
//        if (request == null || request.getExamTitle() == null) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                    .body(new ApiResponse("Invalid request data :(", null));
//        }
//
//        List<QuestionDto> randomQuestions = examService.getQuestionsForExam(request);
//
//        if (randomQuestions.isEmpty()) {
//            return ResponseEntity.status(HttpStatus.NOT_FOUND)
//                    .body(new ApiResponse("No questions found for the requested criteria :(", null));
//        }
//
//        return ResponseEntity.status(HttpStatus.OK)
//                .body(new ApiResponse("Random questions generated successfully for the exam :)", randomQuestions));
//    }



}
