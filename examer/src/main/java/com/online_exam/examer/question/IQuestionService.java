package com.online_exam.examer.question;

import com.online_exam.examer.mapper.PageDto;
import com.online_exam.examer.question.dto.CategoryDto;
import com.online_exam.examer.question.dto.QuestionDto;
import com.online_exam.examer.question.request.AddQuestionRequest;
import com.online_exam.examer.question.request.UpdateQuestionRequest;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface IQuestionService {
    PageDto<QuestionDto> addQuestion(AddQuestionRequest question, String difficulty , Pageable pageable);
    PageDto<QuestionDto>deleteQuestionById(Long QuestionId,  String difficulty  ,Pageable pageable);
    PageDto<QuestionDto> updateQuestionBYId(Long questionId, UpdateQuestionRequest updateQuestionRequest, String difficulty , Pageable pageable);
    QuestionDto getQuestionById(Long QuestionId);
    void addAllQuestions(List<AddQuestionRequest> questions);
    PageDto<CategoryDto>getAvailableCategories(Pageable pageable);
    PageDto<QuestionDto>getAllQuestionsByCategory(String Category, String difficulty ,Pageable pageable);
    CategoryDto getCategoryDetails(String categoryName);
    List<String> getDistinctCategories();

    /****************** Not Used ******************/

    // PageDto<QuestionDto> getAllQuestions(Pageable pageable);
    //PageDto<QuestionDto>getAllQuestionsByDifficulty(String category,String difficulty ,Pageable pageable);
    //PageDto<CategoryWithTotalQuestionDto> getCategoriesWithTotalQuestion(Pageable pageable);

}
