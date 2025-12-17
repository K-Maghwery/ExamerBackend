package com.online_exam.examer.ai_bot;

import com.online_exam.examer.response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
//@RequestMapping("/api/v1/gemini")
public class GeminiController {

    private final GeminiService geminiService;

    public GeminiController(GeminiService geminiService) {
        this.geminiService = geminiService;
    }

    @PostMapping("/prompt")
    public ResponseEntity<ApiResponse> sendPrompt(@RequestBody PromptRequest promptRequest) {
        // Generate questions using GeminiService

        // Return the list of QuestionDto with an HTTP status 200 OK
        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("Successfully To Fetch Data",geminiService.generateQuestions(promptRequest)));
    }
}
