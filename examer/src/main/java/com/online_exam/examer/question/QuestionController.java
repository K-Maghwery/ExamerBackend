package com.online_exam.examer.question;

import com.online_exam.examer.question.request.AddQuestionRequest;
import com.online_exam.examer.question.request.UpdateQuestionRequest;
import com.online_exam.examer.response.ApiResponse;
import com.online_exam.examer.response.GeneralResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class QuestionController {
    private final QuestionService questionService;

    @PostMapping(path = "addQuestion/{difficulty}")
    public ResponseEntity<ApiResponse> addQuestion(@RequestBody @Validated AddQuestionRequest addQuestionRequest, @PathVariable(required = false) String difficulty  , @PageableDefault(size = 5) Pageable pageable) {

        if ("all".equalsIgnoreCase(difficulty)) {
            difficulty = null;
        }
        return ResponseEntity.status(HttpStatus.CREATED).
                body(new ApiResponse("Question added successfully", questionService.addQuestion(addQuestionRequest, difficulty ,pageable)));

    }

    @GetMapping(path = "getQuestionById/{questionid}")
    public ResponseEntity<ApiResponse> getQuestionById(@PathVariable Long questionid) {
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Question retrieved successfully", questionService.getQuestionById(questionid)));
    }

    @PutMapping(path = "updateQuestionById/{questionId}/{difficulty}")
    public ResponseEntity<ApiResponse> updateQuestionBYId(@PathVariable Long questionId, @RequestBody @Validated UpdateQuestionRequest updateQuestionRequest, @PathVariable(required = false) String difficulty , @PageableDefault(size = 5) Pageable pageable) {

        if ("all".equalsIgnoreCase(difficulty)) {
            difficulty = null;
        }

        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("question Updated Successfully", questionService.updateQuestionBYId(questionId, updateQuestionRequest,difficulty,pageable)));

    }

    @DeleteMapping (path ="deleteQuestionById/{questionId}/{difficulty}")
    public ResponseEntity<ApiResponse> deleteQuestionById(@PathVariable Long questionId, @PathVariable(required = false) String difficulty ,@PageableDefault(size = 5) Pageable pageable) {

        if ("all".equalsIgnoreCase(difficulty)) {
            difficulty = null;
        }

        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Question Deleted Successfully", questionService.deleteQuestionById(questionId, difficulty ,pageable)));
    }

    @PostMapping("/addQuestionList")
    public ResponseEntity<GeneralResponse> addAllQuestions(@RequestBody @Validated List<AddQuestionRequest> addAllQuestionRequests) {

        questionService.addAllQuestions(addAllQuestionRequests);
        return ResponseEntity.status(HttpStatus.OK).body(new GeneralResponse(" All Questions added successfully"));

    }

    @GetMapping("getAvailableCategories")
    public ResponseEntity<ApiResponse> getAvailableCategories(@PageableDefault(size = 4) Pageable pageable) {
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Available categories retrieved successfully", questionService.getAvailableCategories(pageable)));
    }

    @GetMapping("getAllQuestionsByCategory/{category}/{difficulty}")
    public ResponseEntity<ApiResponse> getAllQuestionsByCategory(@PathVariable String category, @PathVariable(required = false) String difficulty ,@PageableDefault(size = 5) Pageable pageable) {

        if ("all".equalsIgnoreCase(difficulty)) {
            difficulty = null;
        }
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse("Available categories retrieved successfully", questionService.getAllQuestionsByCategory(category, difficulty ,pageable)));

    }

    @GetMapping("getCategoryDetails/{categoryName}")
    public ResponseEntity<ApiResponse> getCategoryDetails(@PathVariable String categoryName) {
        return ResponseEntity.status(HttpStatus.OK).
                 body(new ApiResponse("Category with it's details retrieved successfully ", questionService.getCategoryDetails(categoryName)));
    }

    @GetMapping("getCategoriesTitle")
    public ResponseEntity<ApiResponse> getCategories() {
        return ResponseEntity.status(HttpStatus.OK).
                body(new ApiResponse(" Categories", questionService.getDistinctCategories()));
    }



    /**************** Not Used End Points **************/

//
//    @GetMapping(path = "getAllQuestions")
//    public ResponseEntity<ApiResponse> getAllQuestions(@PageableDefault(size = 5) Pageable pageable) {
//        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse
//                ("Questions retrieved successfully", questionService.getAllQuestions(pageable)));
//    }
//


//    @GetMapping("getAllQuestionsByDifficulty/{category}/{difficulty}")
//    public ResponseEntity<ApiResponse> getAllQuestionsByDifficulty(@PathVariable String category,@PathVariable(required = false) String difficulty,@PageableDefault(size = 5) Pageable pageable) {
//        return ResponseEntity.status(HttpStatus.OK).
//                body(new ApiResponse("Available categories with difficulty retrieved successfully", questionService.getAllQuestionsByDifficulty(category,difficulty,pageable)));
//
//    }

//
//    @GetMapping("getCategoriesWithTotalQuestions")
//    public ResponseEntity<ApiResponse> getCategoriesWithTotalQuestions(@PageableDefault(size = 4) Pageable pageable) {
//        return ResponseEntity.status(HttpStatus.OK).
//                body(new ApiResponse("Available categories with Questions retrieved successfully", questionService.getCategoriesWithTotalQuestion(pageable)));
//    }

}