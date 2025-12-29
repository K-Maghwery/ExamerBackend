package com.online_exam.examer.user_answers;
import com.online_exam.examer.response.ApiResponse;
import com.online_exam.examer.response.GeneralResponse;
import com.online_exam.examer.user_answers.IUserAnswerService;
import com.online_exam.examer.user_answers.dto.UserAnswerViewDto;
import com.online_exam.examer.user_answers.request.UserAnswerSubmitRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("user-answers")
@RequiredArgsConstructor
public class UserAnswerController {

    private final IUserAnswerService userAnswerService;

    @PostMapping
    public ResponseEntity<GeneralResponse> submitAnswer(
            @RequestBody @Validated UserAnswerSubmitRequest request) {
        userAnswerService.submitAnswer(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new GeneralResponse("Answer submitted successfully"));
    }

    @GetMapping("/submission/{submissionId}")
    public ResponseEntity<ApiResponse> getAnswersBySubmission(
            @PathVariable Long submissionId) {
        List<UserAnswerViewDto> answers = userAnswerService.getAnswersBySubmission(submissionId);
        return ResponseEntity.ok(new ApiResponse("Answers retrieved successfully", answers));
    }

    @GetMapping("/submission/{submissionId}/score")
    public ResponseEntity<ApiResponse> getExamScore(@PathVariable Long submissionId) {
        int score = userAnswerService.calculateScore(submissionId);
        return ResponseEntity.ok(new ApiResponse("Score retrieved successfully", score));
    }
}
