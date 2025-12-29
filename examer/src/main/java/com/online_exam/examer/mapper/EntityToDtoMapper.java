package com.online_exam.examer.mapper;

import com.online_exam.examer.admin.AdminDto;
import com.online_exam.examer.admin.AdminEntity;
import com.online_exam.examer.exam.ExamDto;
import com.online_exam.examer.exam.ExamEntity;
import com.online_exam.examer.exam_submission.dto.ExamQuestionsDto;

import com.online_exam.examer.question.*;
import com.online_exam.examer.question.dto.OptionDto;
import com.online_exam.examer.question.dto.QuestionDto;
import com.online_exam.examer.question.enums.QuestionType;
import com.online_exam.examer.question.request.AddQuestionRequest;
import com.online_exam.examer.user.UserDto;
import com.online_exam.examer.user.UserEntity;
import com.online_exam.examer.user_answers.UserAnswerEntity;
import com.online_exam.examer.user_answers.UserAnswerOptionEntity;
import com.online_exam.examer.user_answers.dto.UserAnswerViewDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class EntityToDtoMapper {

    public AdminDto adminToDto(AdminEntity adminEntity) {
        if (adminEntity == null) {
            return null;
        }

        AdminDto adminDto = new AdminDto();
        adminDto.setAdminId(adminEntity.getAdminId());
        adminDto.setAdminUserName(adminEntity.getAdminUserName());
        adminDto.setPhone(adminEntity.getPhone());
        adminDto.setEmail(adminEntity.getEmail());
//        adminDto.setPassword(adminEntity.getPassword());
//        adminDto.setRole(adminEntity.getRole());

        return adminDto;
    }



    public ExamDto examToDto(ExamEntity exam) {
        ExamDto examDto = new ExamDto();
        examDto.setExamId(exam.getExamId());
        examDto.setExamTitle(exam.getExamTitle());
        examDto.setExamDescription(exam.getExamDescription());
        examDto.setExamDuration(exam.getExamDuration());
        examDto.setEasy(exam.getEasy());
        examDto.setMedium(exam.getMedium());
        examDto.setHard(exam.getHard());
        examDto.setCreatedDate(exam.getCreatedDate());
        examDto.setAdminId(exam.getAdmin().getAdminId());
        return examDto;
    }


    // Helper method to map QuestionEntity to ExamQuestionsDto
//    public ExamQuestionsDto questionToExamQuestionsDto(QuestionEntity questionEntity) {
//        ExamQuestionsDto dto = new ExamQuestionsDto();
//        dto.setQuestionId(questionEntity.getQuestionId());
//        dto.setQuestionContent(questionEntity.getQuestionContent());
//        dto.setOption1(questionEntity.getOption1());
//        dto.setOption2(questionEntity.getOption2());
//        dto.setOption3(questionEntity.getOption3());
//        dto.setOption4(questionEntity.getOption4());
//        dto.setCorrectAnswer(questionEntity.getCorrectAnswer());
//        return dto;
//    }

    public ExamQuestionsDto questionToExamQuestionsDto(QuestionEntity questionEntity) {
        if (questionEntity == null) {
            return null;
        }

        ExamQuestionsDto dto = new ExamQuestionsDto();
        dto.setQuestionId(questionEntity.getQuestionId());
        dto.setQuestionContent(questionEntity.getQuestionContent());
        dto.setQuestionType(questionEntity.getQuestionType());

        // WRITTEN question → options = null
        if (questionEntity.getQuestionType() == QuestionType.WRITTEN) {
            dto.setOptions(null);
            dto.setCorrectOptionIndexes(List.of());
            return dto;
        }

        List<String> optionTexts = new ArrayList<>();
        List<Integer> correctIndexes = new ArrayList<>();

        List<QuestionOptionEntity> options = questionEntity.getOptions();
        for (int i = 0; i < options.size(); i++) {
            QuestionOptionEntity option = options.get(i);
            optionTexts.add(option.getOptionText());

            if (Boolean.TRUE.equals(option.getIsCorrect())) {
                correctIndexes.add(i);
            }
        }

        dto.setOptions(optionTexts);
        dto.setCorrectOptionIndexes(correctIndexes);

        return dto;
    }

    public List<ExamQuestionsDto> questionsToExamQuestionsDtoList(List<QuestionEntity> questionEntities) {
        return questionEntities.stream().map(this::questionToExamQuestionsDto).collect(Collectors.toList());
    }


// I need to make new dto for return userdto with and without examsubmission list
    public UserDto userToDto(UserEntity user) {
        if (user == null) {
            return null;
        }

        UserDto userDto = new UserDto();
        userDto.setUserId(user.getUserId());
        userDto.setUserName(user.getUserName());
        userDto.setEmail(user.getEmail());
        userDto.setPhone(user.getPhone());
//
//        // Map each ExamSubmissionEntity to ExamSubmissionDto
//       List<ExamSubmissionDto> examSubmissionDtos = user.getExamSubmission().stream()
//                .map(this::examSubmissionToDto) // Map each ExamSubmissionEntity to ExamSubmissionDto
//                .collect(Collectors.toList());
//        userDto.setExamSubmissions(examSubmissionDtos);

        return userDto;
    }

    public List<UserDto> usersToDtoList(List<UserEntity> users) {
        return users.stream().map(this::userToDto).collect(Collectors.toList());
    }

//    public QuestionDto questionToDto(QuestionEntity questionEntity) {
//        if (questionEntity == null) {
//            return null;
//        }
//        QuestionDto dto = new QuestionDto();
//        dto.setQuestionId(questionEntity.getQuestionId());
//        dto.setQuestionContent(questionEntity.getQuestionContent());
//        dto.setOption1(questionEntity.getOption1());
//        dto.setOption2(questionEntity.getOption2());
//        dto.setOption3(questionEntity.getOption3());
//        dto.setOption4(questionEntity.getOption4());
//        dto.setCategory(questionEntity.getCategory());
//        dto.setDifficulty(questionEntity.getDifficulty());
//        dto.setCorrectAnswer(questionEntity.getCorrectAnswer());
//        return dto;
//    }


    public QuestionDto questionToDto(QuestionEntity questionEntity) {

        if (questionEntity == null) {
            return null;
        }

        QuestionDto dto = new QuestionDto();
        dto.setQuestionId(questionEntity.getQuestionId());
        dto.setQuestionContent(questionEntity.getQuestionContent());
        dto.setCategory(questionEntity.getCategory());
        dto.setDifficulty(questionEntity.getDifficulty());
        dto.setQuestionType(questionEntity.getQuestionType());

        // WRITTEN questions → no options
        if (questionEntity.getQuestionType() == QuestionType.WRITTEN) {
            dto.setOptions(null);
            dto.setCorrectOptionIndexes(List.of());
            return dto;
        }

        List<String> options = new ArrayList<>();
        List<Integer> correctIndexes = new ArrayList<>();

        List<QuestionOptionEntity> optionEntities = questionEntity.getOptions();

        for (int i = 0; i < optionEntities.size(); i++) {
            QuestionOptionEntity option = optionEntities.get(i);

            // ✅ ONLY option text
            options.add(option.getOptionText());

            // ✅ store index of correct option
            if (Boolean.TRUE.equals(option.getIsCorrect())) {
                correctIndexes.add(i);
            }
        }

        dto.setOptions(options);
        dto.setCorrectOptionIndexes(correctIndexes);

        return dto;
    }





    // New method to convert Page<AdminEntity> to Page<AdminDto>
    public Page<AdminDto> adminsPageToDtoPage(Page<AdminEntity> adminEntitiesPage) {
        List<AdminDto> adminDtos = adminEntitiesPage.getContent().stream()
                .map(this::adminToDto)  // Use your existing adminToDto method
                .collect(Collectors.toList());

        // Return a PageImpl for pagination support
        return new PageImpl<>(adminDtos, adminEntitiesPage.getPageable(), adminEntitiesPage.getTotalElements());
    }

    // New method to convert Page<ExamEntity> to Page<ExamDto>
    public Page<ExamDto> examsPageToDtoPage(Page<ExamEntity> examEntitiesPage) {
        List<ExamDto> examDtos = examEntitiesPage.getContent().stream()
                .map(this::examToDto)  // Use your existing examToDto method
                .collect(Collectors.toList());

        // Return a PageImpl for pagination support
        return new PageImpl<>(examDtos, examEntitiesPage.getPageable(), examEntitiesPage.getTotalElements());
    }


    // New method to convert Page<QuestionEntity> to Page<QuestionDto>
    public Page<QuestionDto> questionsPageToDtoPage(Page<QuestionEntity> questionEntitiesPage) {
        List<QuestionDto> questionDtos = questionEntitiesPage.getContent().stream()
                .map(this::questionToDto)  // Use your existing questionToDto method
                .collect(Collectors.toList());

        // Return a PageImpl for pagination support
        return new PageImpl<>(questionDtos, questionEntitiesPage.getPageable(), questionEntitiesPage.getTotalElements());
    }



    // New method to convert Page<UserEntity> to Page<UserDto>
    public Page<UserDto> usersPageToDtoPage(Page<UserEntity> userEntitiesPage) {
        List<UserDto> userDtos = userEntitiesPage.getContent().stream()
                .map(this::userToDto)  // Use your existing userToDto method
                .collect(Collectors.toList());

        // Return a PageImpl for pagination support
        return new PageImpl<>(userDtos, userEntitiesPage.getPageable(), userEntitiesPage.getTotalElements());
    }


//    public QuestionEntity convertAddQuestionRequestToEntity(AddQuestionRequest addQuestionRequest) {
//        QuestionEntity questionEntity = new QuestionEntity();
//        questionEntity.setQuestionContent(addQuestionRequest.getQuestionContent());
//        questionEntity.setQuestionType(addQuestionRequest.getQuestionType());
//        questionEntity.setOption1(addQuestionRequest.getOption1());
//        questionEntity.setOption2(addQuestionRequest.getOption2());
//        questionEntity.setOption3(addQuestionRequest.getOption3());
//        questionEntity.setOption4(addQuestionRequest.getOption4());
//        questionEntity.setCorrectAnswer(addQuestionRequest.getCorrectAnswer());
//        questionEntity.setCategory(addQuestionRequest.getCategory());
//        questionEntity.setCategory(addQuestionRequest.getCategory());
//        questionEntity.setDifficulty(addQuestionRequest.getDifficulty());
//        return questionEntity;
//    }

    public QuestionEntity convertAddQuestionRequestToEntity(AddQuestionRequest addQuestionRequest) {

        QuestionEntity questionEntity = new QuestionEntity();
        questionEntity.setQuestionContent(addQuestionRequest.getQuestionContent());
        questionEntity.setCategory(addQuestionRequest.getCategory());
        questionEntity.setDifficulty(addQuestionRequest.getDifficulty());
        questionEntity.setQuestionType(addQuestionRequest.getQuestionType());

        // For WRITTEN questions → no options
        if (addQuestionRequest.getQuestionType() == QuestionType.WRITTEN) {
            questionEntity.setOptions(null);
            return questionEntity;
        }

        // Build options for MCQ / TF
        List<QuestionOptionEntity> options = new ArrayList<>();
        List<String> optionTexts = addQuestionRequest.getOptions();
        List<Integer> correctIndexes = addQuestionRequest.getCorrectOptionIndexes();

        for (int i = 0; i < optionTexts.size(); i++) {
            QuestionOptionEntity option = new QuestionOptionEntity();
            option.setOptionText(optionTexts.get(i));
            option.setIsCorrect(correctIndexes.contains(i));
            option.setQuestion(questionEntity); // link option to question
            options.add(option);
        }

        questionEntity.setOptions(options);

        return questionEntity;
    }



    public List<QuestionEntity> convertAddQuestionListToEntityList(List<AddQuestionRequest> addAllQuestionRequests) {

        return addAllQuestionRequests.stream()
                .map(this::convertAddQuestionRequestToEntity)
                .collect(Collectors.toList());
    }


    /******************** USER ANSWERS MAPPER ********************/

// Convert a single UserAnswerEntity to UserAnswerViewDto
    public UserAnswerViewDto userAnswerToDto(UserAnswerEntity entity) {
        if (entity == null) {
            return null;
        }

        UserAnswerViewDto dto = new UserAnswerViewDto();

        // Basic question info
        dto.setQuestionId(entity.getQuestion().getQuestionId());

        // Written answer (for WRITTEN questions)
        dto.setWrittenAnswer(entity.getWrittenAnswer());

        // If question type is WRITTEN → no selected options
        if (entity.getQuestion().getQuestionType() == QuestionType.WRITTEN) {
            dto.setSelectedOptions(List.of());
            return dto;
        }

        // MCQ / TF → map selected options
        List<OptionDto> selectedOptions = new ArrayList<>();
        if (entity.getSelectedOptions() != null) {
            for (UserAnswerOptionEntity uao : entity.getSelectedOptions()) {
                OptionDto optionDto = new OptionDto();
                optionDto.setOptionId(uao.getOption().getOptionId());
                optionDto.setOptionText(uao.getOption().getOptionText());
                selectedOptions.add(optionDto);
            }
        }

        dto.setSelectedOptions(selectedOptions);
        return dto;
    }

    // Convert a list of UserAnswerEntity to List<UserAnswerViewDto>
    public List<UserAnswerViewDto> userAnswersToDtoList(List<UserAnswerEntity> entities) {
        return entities.stream()
                .map(this::userAnswerToDto)
                .collect(Collectors.toList());
    }






    /************************* Not Used ***************************/

//    public List<AdminDto> adminsToDtoList(List<AdminEntity> adminEntities) {
//        return adminEntities.stream()
//                .map(this::adminToDto)
//                .collect(Collectors.toList());
//    }
//

//    public ExamDropListDto examToDropListDto(ExamEntity examEntity) {
//        if (examEntity == null) {
//            return null;
//        }
//        ExamDropListDto dto = new ExamDropListDto();
//        dto.setExamId(examEntity.getExamId());
//        dto.setExamTitle(examEntity.getExamTitle());
//
//        return dto;
//    }
//
//    public List<ExamDropListDto> examsToDropListDtoList(List<ExamEntity> examEntities) {
//        return examEntities.stream().map(this::examToDropListDto).collect(Collectors.toList());
//    }

//
//    // Helper method to map ExamSubmissionEntity to ExamSubmissionDto
//    private ExamSubmissionDto examSubmissionToDto(ExamSubmissionEntity examSubmissionEntity) {
//        if (examSubmissionEntity == null) {
//            return null;
//        }
//
//        ExamSubmissionDto examSubmissionDto = new ExamSubmissionDto();
//        examSubmissionDto.setExamSubmissionId(examSubmissionEntity.getExamSubmissionId());
//        examSubmissionDto.setScore(examSubmissionEntity.getScore());
//        examSubmissionDto.setStatus(examSubmissionEntity.isStatus());
//        examSubmissionDto.setCreatedDate(examSubmissionEntity.getCreatedDate());
//
//        return examSubmissionDto;
//    }

    //
//    public Page<AssignExamToUserDto> examSubmissionsPageToAssignExamDtoPage(Page<ExamSubmissionEntity> examSubmissionEntitiesPage) {
//        List<AssignExamToUserDto> assignExamToUserDtos = examSubmissionEntitiesPage.getContent().stream()
//                .map(this::examSubmissionToAssignExamDto)  // Use your existing examSubmissionToAssignExamDto method
//                .collect(Collectors.toList());
//
//        // Return a PageImpl with pagination support
//        return new PageImpl<>(assignExamToUserDtos, examSubmissionEntitiesPage.getPageable(), examSubmissionEntitiesPage.getTotalElements());
//    }

//    public PageDto<CategoryWithTotalQuestionDto> categoryDtoToCategoriesWithTotalQuestionDto(Page<CategoryDto> categoryDtos) {
//        if (categoryDtos == null) {
//            return null;
//        }
//
//        // Map each CategoryDto to CategoryWithTotalQuestionDto
//        List<CategoryWithTotalQuestionDto> mappedContent = categoryDtos.getContent().stream()
//                .map(categoryDto -> new CategoryWithTotalQuestionDto(
//                        categoryDto.getCategoryName(),
//                        categoryDto.getNum_totalQuestions()
//                ))
//                .collect(Collectors.toList());
//
//        // Create and return a new PageDto with the mapped content and pagination metadata
//        return new PageDto<>(
//                new PageImpl<>(mappedContent, categoryDtos.getPageable(), categoryDtos.getTotalElements())
//        );
//    }
//
//    public List<CategoryWithTotalQuestionDto> CategoryQuestionToDtoList(List<CategoryDto> categoriesDto) {
//        return categoriesDto.stream()
//                .map(this::CategoryQuestionToDto)
//                .collect(Collectors.toList());
//    }

//    public List<QuestionDto> questionsToDtoList(List<QuestionEntity> questionEntities) {
//        return questionEntities.stream()
//                .map(this::questionToDto)
//                .collect(Collectors.toList());
//    }
//
//    public CategoryWithTotalQuestionDto CategoryQuestionToDto(CategoryDto categoryDto) {
//        if (categoryDto == null) {
//            return null;
//        }
//        CategoryWithTotalQuestionDto dto = new CategoryWithTotalQuestionDto();
//        dto.setCategoryName(categoryDto.getCategoryName());
//        dto.setNum_totalQuestions(categoryDto.getNum_totalQuestions());
//        return dto;
//    }

//
//    public List<AssignExamToUserDto> examSubmissionToAssignExamDtoList(List<ExamSubmissionEntity> examSubmissions) {
//        return examSubmissions.stream().map(this::examSubmissionToAssignExamDto).collect(Collectors.toList());
//    }


//    public List<ExamDto> examsToDtoList(List<ExamEntity> exams) {
//        return exams.stream().map(this::examToDto).collect(Collectors.toList());
//    }
//
//    public AssignExamToUserDto examSubmissionToAssignExamDto(ExamSubmissionEntity examSubmissionEntity) {
//
//        AssignExamToUserDto assignExamToUserDto = new AssignExamToUserDto();
//        assignExamToUserDto.setUserName(examSubmissionEntity.getUser().getUserName());
//        assignExamToUserDto.setEmail(examSubmissionEntity.getUser().getEmail());
//        assignExamToUserDto.setPhone(examSubmissionEntity.getUser().getPhone());
//        return assignExamToUserDto;
//    }

}
