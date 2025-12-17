package com.online_exam.examer.question.request;

import lombok.Data;
import com.online_exam.examer.question.enums.QuestionType;
import jakarta.validation.constraints.*;
import java.util.List;

@Data
public class AddQuestionRequest {
 private String questionContent;

 private String difficulty;

 private String category;

 private QuestionType questionType;

 private List<String> options;

 private List<Integer> correctOptionIndexes;
}
