package com.online_exam.examer.question;

import com.online_exam.examer.exception.AlreadyExsistsException;
import com.online_exam.examer.exception.ResourceNotFoundException;
import com.online_exam.examer.mapper.EntityToDtoMapper;
import com.online_exam.examer.mapper.PageDto;
import com.online_exam.examer.question.dto.CategoryDto;
import com.online_exam.examer.question.dto.QuestionDto;
import com.online_exam.examer.question.enums.QuestionType;
import com.online_exam.examer.question.request.AddQuestionRequest;
import com.online_exam.examer.question.request.UpdateQuestionRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@RequiredArgsConstructor
public class QuestionService implements IQuestionService {

    private final QuestionRepository questionRepositary;
    private final EntityToDtoMapper entityToDtoMapper;



//    public PageDto<QuestionDto> addQuestion(AddQuestionRequest addQuestionRequest, String difficulty, Pageable pageable) {
//        // Validate if options are unique
//        if (!areOptionsUnique(
//                addQuestionRequest.getOptions(),addQuestionRequest.getQuestionType())) {
//            throw new IllegalArgumentException("Options must be unique");
//        }
//        // Validate if the correct answer is valid
//        if (!isCorrectAnswerValid( addQuestionRequest.getCorrectOptionIndexes(),addQuestionRequest.getOptions(),addQuestionRequest.getQuestionType())) {
//            throw new IllegalArgumentException("The correct answer must be one of the provided options");
//        }
//
//
//        QuestionEntity questionEntity = new QuestionEntity();
//        questionEntity.setQuestionContent(addQuestionRequest.getQuestionContent());
//        questionEntity.setOption1(addQuestionRequest.getOption1());
//        questionEntity.setOption2(addQuestionRequest.getOption2());
//        questionEntity.setOption3(addQuestionRequest.getOption3());
//        questionEntity.setOption4(addQuestionRequest.getOption4());
//        questionEntity.setCategory(addQuestionRequest.getCategory());
//        questionEntity.setCorrectAnswer(addQuestionRequest.getCorrectAnswer());
//        questionEntity.setDifficulty(addQuestionRequest.getDifficulty());
//        questionRepositary.save(questionEntity);
//        Page<QuestionEntity> questions=questionRepositary.findByCategory(addQuestionRequest.getCategory(), difficulty ,pageable);
//        // Convert the Page<QuestionEntity> to Page<QuestionDto>
//        Page<QuestionDto> questionsPageDto = entityToDtoMapper.questionsPageToDtoPage(questions);
//
//        // Wrap the Page<QuestionDto> into PageDto<QuestionDto> to return only necessary data
//        return new PageDto<>(questionsPageDto);
//    }

    @Transactional
    @Override
    public PageDto<QuestionDto> addQuestion(AddQuestionRequest addQuestionRequest, String difficulty, Pageable pageable) {


        if (!areOptionsUnique(addQuestionRequest.getOptions(), addQuestionRequest.getQuestionType())) {
            throw new IllegalArgumentException("Options must be unique");
        }


        if (!isCorrectAnswerValid(addQuestionRequest.getCorrectOptionIndexes(),
                addQuestionRequest.getOptions(),
                addQuestionRequest.getQuestionType())) {
            throw new IllegalArgumentException("The correct answer must be one of the provided options");
        }


        QuestionEntity questionEntity = entityToDtoMapper.convertAddQuestionRequestToEntity(addQuestionRequest);


        questionRepositary.save(questionEntity);


        Page<QuestionEntity> questions = questionRepositary.findByCategoryAndDifficultyAndNotDeleted(
                addQuestionRequest.getCategory(),
                difficulty,
                pageable
        );

        // Convert the Page<QuestionEntity> to Page<QuestionDto>
        Page<QuestionDto> questionsPageDto = entityToDtoMapper.questionsPageToDtoPage(questions);

        // Wrap the Page<QuestionDto> into PageDto<QuestionDto> to return only necessary data
        return new PageDto<>(questionsPageDto);
    }


    @Transactional
    @Override
    public PageDto<QuestionDto>deleteQuestionById(Long QuestionId, String difficulty ,Pageable pageable) {
        // Check if the question exists
        if (!questionRepositary.existsById(QuestionId)) {
            throw new ResourceNotFoundException("Question not found ");
        }
        // Check if the question is assigned to any exam
        if(questionRepositary.existsByIdAndAssignedToAnyExam(QuestionId)){
            throw new AlreadyExsistsException("This question cannot be deleted as it is already assigned to an exam.");
        }

        QuestionEntity questionEntity = questionRepositary.findById(QuestionId).get();
        questionEntity.setDeleted(true);
        questionRepositary.save(questionEntity);

//        questionRepositary.deleteById(QuestionId);

        // Fetch the all questions with pagination
        Page<QuestionEntity> questions = questionRepositary.findByCategory(questionEntity.getCategory(), difficulty ,pageable);

        // Convert the Page<QuestionEntity> to Page<QuestionDto>
        Page<QuestionDto> questionsPageDto = entityToDtoMapper.questionsPageToDtoPage(questions);

        // Wrap the Page<QuestionDto> into PageDto<QuestionDto> to return only necessary data
        return new PageDto<>(questionsPageDto);

    }

//    @Transactional
//    @Override
//    public PageDto<QuestionDto> updateQuestionBYId(Long questionId, UpdateQuestionRequest updateQuestionRequest, String difficulty, Pageable pageable) {
//        // Check if the question exists and is not soft deleted
//        QuestionEntity savedQuestion = questionRepositary.findByQuestionIdAndIsDeletedFalse(questionId)
//                .orElseThrow(() -> new ResourceNotFoundException("Question not found"));
////        if (!questionRepositary.existsById(questionId)) {
////            throw new ResourceNotFoundException("Question not found");
////        }
////        QuestionEntity savedQuestion = questionRepositary.findById(questionId).get();
//        // Update the question details
//        savedQuestion.setQuestionContent(updateQuestionRequest.getQuestionContent());
//        savedQuestion.setOption1(updateQuestionRequest.getOption1());
//        savedQuestion.setOption2(updateQuestionRequest.getOption2());
//        savedQuestion.setOption3(updateQuestionRequest.getOption3());
//        savedQuestion.setOption4(updateQuestionRequest.getOption4());
//        savedQuestion.setCategory(updateQuestionRequest.getCategory());
//        savedQuestion.setCorrectAnswer(updateQuestionRequest.getCorrectAnswer());
//        savedQuestion.setDifficulty(updateQuestionRequest.getDifficulty());
//        // Validate if options are unique
//        if (!areOptionsUnique(
//                updateQuestionRequest.getOptions(), updateQuestionRequest.getQuestionType())) {
//            throw new IllegalArgumentException("Options must be unique");
//        }
//        // Validate if the correct answer is valid
//        if (!isCorrectAnswerValid(updateQuestionRequest.getCorrectOptionIndexes(),updateQuestionRequest.getOptions(),updateQuestionRequest.getQuestionType())) {
//            throw new IllegalArgumentException("The correct answer must be one of the provided options");
//        }
//        questionRepositary.save(savedQuestion);
//        // If difficulty is null, it means we need to return all questions
//        if (difficulty == null) {
//// Fetch all questions with pagination
//            Page<QuestionEntity> questions = questionRepositary.findByCategoryAndIsDeletedFalse(
//                    updateQuestionRequest.getCategory(),
//                    pageable
//            );
//
//// Convert the Page<QuestionEntity> to Page<QuestionDto>
//            Page<QuestionDto> questionsPageDto = entityToDtoMapper.questionsPageToDtoPage(questions);
//
//// Wrap the Page<QuestionDto> into PageDto<QuestionDto> to return only necessary data
//            return new PageDto<>(questionsPageDto);
//        }
//
//        // Otherwise, fetch questions with specific difficulty
//        Page<QuestionEntity> questions = questionRepositary.findByCategoryAndDifficultyAndDeleted(
//                updateQuestionRequest.getCategory(),
//                difficulty, false,
//                pageable
//        );
//
//        // Convert the Page<QuestionEntity> to Page<QuestionDto>
//        Page<QuestionDto> questionsPageDto = entityToDtoMapper.questionsPageToDtoPage(questions);
//
//        // Wrap the Page<QuestionDto> into PageDto<QuestionDto> to return only necessary data
//        return new PageDto<>(questionsPageDto);
//
//    }


    public PageDto<QuestionDto> updateQuestionBYId(Long questionId, UpdateQuestionRequest updateQuestionRequest, String difficulty, Pageable pageable) {


        QuestionEntity savedQuestion = questionRepositary.findByQuestionIdAndIsDeletedFalse(questionId)
                .orElseThrow(() -> new ResourceNotFoundException("Question not found"));


        if (!areOptionsUnique(updateQuestionRequest.getOptions(), updateQuestionRequest.getQuestionType())) {
            throw new IllegalArgumentException("Options must be unique");
        }


        if (!isCorrectAnswerValid(updateQuestionRequest.getCorrectOptionIndexes(),
                updateQuestionRequest.getOptions(),
                updateQuestionRequest.getQuestionType())) {
            throw new IllegalArgumentException("The correct answer must be one of the provided options");
        }


        savedQuestion.setQuestionContent(updateQuestionRequest.getQuestionContent());
        savedQuestion.setCategory(updateQuestionRequest.getCategory());
        savedQuestion.setDifficulty(updateQuestionRequest.getDifficulty());
        savedQuestion.setQuestionType(updateQuestionRequest.getQuestionType());


        if (updateQuestionRequest.getQuestionType() == QuestionType.WRITTEN) {
            savedQuestion.setOptions(null); // no options for written
        } else {
            List<QuestionOptionEntity> updatedOptions = new ArrayList<>();
            List<String> optionTexts = updateQuestionRequest.getOptions();
            List<Integer> correctIndexes = updateQuestionRequest.getCorrectOptionIndexes();

            for (int i = 0; i < optionTexts.size(); i++) {
                QuestionOptionEntity option = new QuestionOptionEntity();
                option.setOptionText(optionTexts.get(i));
                option.setIsCorrect(correctIndexes.contains(i));
                option.setQuestion(savedQuestion); // link to question
                updatedOptions.add(option);
            }

            // Remove old options and set new ones
            savedQuestion.getOptions().clear();
            savedQuestion.getOptions().addAll(updatedOptions);
        }


        questionRepositary.save(savedQuestion);


                // If difficulty is null, it means we need to return all questions
        if (difficulty == null) {
// Fetch all questions with pagination
            Page<QuestionEntity> questions = questionRepositary.findByCategoryAndIsDeletedFalse(
                    updateQuestionRequest.getCategory(),
                    pageable
            );

// Convert the Page<QuestionEntity> to Page<QuestionDto>
            Page<QuestionDto> questionsPageDto = entityToDtoMapper.questionsPageToDtoPage(questions);

// Wrap the Page<QuestionDto> into PageDto<QuestionDto> to return only necessary data
            return new PageDto<>(questionsPageDto);
        }

        // Otherwise, fetch questions with specific difficulty
        Page<QuestionEntity> questions = questionRepositary.findByCategoryAndDifficultyAndDeleted(
                updateQuestionRequest.getCategory(),
                difficulty, false,
                pageable
        );

        // Convert the Page<QuestionEntity> to Page<QuestionDto>
        Page<QuestionDto> questionsPageDto = entityToDtoMapper.questionsPageToDtoPage(questions);

        // Wrap the Page<QuestionDto> into PageDto<QuestionDto> to return only necessary data
        return new PageDto<>(questionsPageDto);

    }


    @Transactional(readOnly = true)
    @Override
    public QuestionDto getQuestionById(Long QuestionId) {
        // Fetch the question while ensuring it is not soft-deleted
        Optional<QuestionEntity> optionalQuestion = questionRepositary.findByQuestionIdAndIsDeletedFalse(QuestionId);

        if (optionalQuestion.isEmpty()) {
            throw new ResourceNotFoundException("Question not found");
        }

        QuestionEntity question = optionalQuestion.get();
        return entityToDtoMapper.questionToDto(question);

//        if (!questionRepositary.existsById(QuestionId)) {
//            throw new ResourceNotFoundException("Question not found ");
//        }
//        QuestionEntity question = questionRepositary.findById(QuestionId).get();
//        return entityToDtoMapper.questionToDto(question);
    }


    @Transactional
    @Override
    public void addAllQuestions(List<AddQuestionRequest> addAllQuestionRequests) {
        List<QuestionEntity> questionEntities =entityToDtoMapper.convertAddQuestionListToEntityList(addAllQuestionRequests);
        questionRepositary.saveAll(questionEntities);

    }

    @Transactional(readOnly = true)
    @Override
    public PageDto<CategoryDto> getAvailableCategories(Pageable pageable) {

//        Page<CategoryDto> categoryDtos = questionRepositary.getAvailableCategories(pageable);
        // Fetch categories based on the condition that questions in the category are not deleted
        Page<CategoryDto> categoryDtos = questionRepositary.findCategoriesWithActiveQuestions(pageable);
        return new PageDto<>(categoryDtos);

    }



    @Transactional(readOnly = true)
    @Override
    public PageDto<QuestionDto>getAllQuestionsByCategory(String category, String difficulty ,Pageable pageable){
        Page<QuestionEntity> questions=questionRepositary.findByCategoryAndDifficultyAndNotDeleted(category, difficulty ,pageable);
        // Convert the Page<QuestionEntity> to Page<QuestionDto>
        Page<QuestionDto> questionsPageDto = entityToDtoMapper.questionsPageToDtoPage(questions);

        // Wrap the Page<QuestionDto> into PageDto<QuestionDto> to return only necessary data
        return new PageDto<>(questionsPageDto);
    }



    @Transactional(readOnly = true)
    @Override
    public CategoryDto getCategoryDetails(String categoryName) {
        return questionRepositary.findCategoryDetailsByCategoryAndNotDeleted(categoryName);
    }

   @Transactional(readOnly = true)
    @Override
    public List<String> getDistinctCategories() {
        List<String>categories=questionRepositary.findDistinctCategoriesWithActiveQuestions();
       return categories;
    }


    // Helper method to validate unique options
    private boolean areOptionsUnique(List<String> options, QuestionType questionType) {
        if(questionType==QuestionType.WRITTEN){
            return true;
        }

        Set<String> uniqueOptions = new HashSet<>();
        for (String option : options) {
                uniqueOptions.add(option.trim()); // trim to avoid spaces being counted as different
        }

        return uniqueOptions.size() == options.size();
//        Set<String> options = new HashSet<>();
//        options.add(option1);
//        options.add(option2);
//        options.add(option3);
//        options.add(option4);
//        return options.size() == 4; // All options should be unique
    }



    // Helper method to validate correct answer
//    private boolean isCorrectAnswerValid(String correctAnswer, String option1, String option2, String option3, String option4) {
//        return correctAnswer.equals(option1) ||
//                correctAnswer.equals(option2) ||
//                correctAnswer.equals(option3) ||
//                correctAnswer.equals(option4);
//    }

    private boolean isCorrectAnswerValid(List<Integer> correctOptionIndexes, List<String> options, QuestionType questionType) {

        if (questionType == QuestionType.WRITTEN) {
            return true;
        }


        // Each index must be within options range
        for (Integer index : correctOptionIndexes) {
            if (index < 0 || index >= options.size()) {
                return false;
            }
        }

        return true;
    }


    /****************** Not Used ******************/

//    @Transactional(readOnly = true)
//    @Override
//    public PageDto<QuestionDto> getAllQuestions(Pageable pageable) {
//        // Fetch all non-deleted questions with pagination
//        Page<QuestionEntity> questions = questionRepositary.findAllByIsDeletedFalse(pageable);
//
//
//        // Convert the Page<QuestionEntity> to Page<QuestionDto>
//        Page<QuestionDto> questionsPageDto = entityToDtoMapper.questionsPageToDtoPage(questions);
//
//        // Wrap the Page<QuestionDto> into PageDto<QuestionDto> to return only necessary data
//        return new PageDto<>(questionsPageDto);
//
//    }
//
//    @Transactional(readOnly = true)
//    @Override
//    public PageDto<CategoryWithTotalQuestionDto> getCategoriesWithTotalQuestion(Pageable pageable) {
//        Page<CategoryDto> categoryDtos = questionRepositary.findCategoriesWithActiveQuestions(pageable);
//
//        return entityToDtoMapper.categoryDtoToCategoriesWithTotalQuestionDto(categoryDtos);
//
//
//    }

    //    @Transactional(readOnly = true)
//    @Override
//    public PageDto<QuestionDto>getAllQuestionsByDifficulty(String category,String difficulty ,Pageable pageable){
//
//        Page<QuestionEntity> questions=questionRepositary.findByCategoryAndDifficulty(category,difficulty,pageable);
//        // Convert the Page<QuestionEntity> to Page<QuestionDto>
//        Page<QuestionDto> questionsPageDto = entityToDtoMapper.questionsPageToDtoPage(questions);
//
//        // Wrap the Page<QuestionDto> into PageDto<QuestionDto> to return only necessary data
//        return new PageDto<>(questionsPageDto);
//    }


}


