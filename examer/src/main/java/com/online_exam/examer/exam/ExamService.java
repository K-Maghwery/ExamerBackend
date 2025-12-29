package com.online_exam.examer.exam;

import com.online_exam.examer.admin.AdminEntity;
import com.online_exam.examer.admin.AdminRepository;
import com.online_exam.examer.exception.ResourceNotFoundException;
import com.online_exam.examer.mapper.EntityToDtoMapper;
import com.online_exam.examer.mapper.PageDto;
import com.online_exam.examer.question.QuestionEntity;
import com.online_exam.examer.question.QuestionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ExamService implements IExamService {

    private final ExamRepository examRepository;
    private final AdminRepository adminRepository;
    private final EntityToDtoMapper entityToDtoMapper;
    private final QuestionRepository questionRepositary;


    @Transactional
//    @Caching(evict = {
//            @CacheEvict(value = "questionsOfExam", allEntries = true),
//            @CacheEvict(value = "getAllExamsByAdminId", allEntries = true)
//    })
    @Override
    public void addExam(AddExamRequest addExamRequest) {


        if(!adminRepository.existsById(addExamRequest.getAdminId())) {
            throw new ResourceNotFoundException("Admin does not exist");
        }
        AdminEntity admin = adminRepository.findById(addExamRequest.getAdminId()).get();




        ExamEntity examEntity = new ExamEntity();
        examEntity.setExamTitle(addExamRequest.getCategoryName());
        examEntity.setExamTitle(addExamRequest.getExamTitle());
        examEntity.setExamDescription(addExamRequest.getExamDescription());
        examEntity.setExamDuration(addExamRequest.getExamDuration());
        examEntity.setEasy(addExamRequest.getEasy());
        examEntity.setMedium(addExamRequest.getMedium());
        examEntity.setHard(addExamRequest.getHard());
        examEntity.setCreatedDate(new Timestamp(System.currentTimeMillis()));
        examEntity.setAdmin(admin);
        examEntity.setAssignedQuestions(getQuestionsForExam(addExamRequest.getCategoryName(),addExamRequest.getEasy(),addExamRequest.getMedium(),addExamRequest.getHard()));
        examRepository.save(examEntity);



    }

    @Transactional
//    @Caching(evict = {
//            @CacheEvict(value = "questionsOfExam", allEntries = true),
//            @CacheEvict(value = "getAllExamsByAdminId", allEntries = true)
//    })
    @Override
    public PageDto<ExamDto> deleteExamById(Long examId, Pageable pageable) {
        if(!examRepository.existsById(examId)) {
            throw new ResourceNotFoundException("Exam does not exist");
        }

        ExamEntity deletedExam = examRepository.findById(examId).get();

        AdminEntity admin = deletedExam.getAdmin();

        examRepository.deleteById(examId);

        // Fetch the remaining exams with pagination
        Page<ExamEntity> remainingExamsPage = examRepository.findAllByAdmin_AdminId(admin.getAdminId(),pageable);

        // Convert the Page<ExamEntity> to Page<ExamDto>
        Page<ExamDto> examsPageDto = entityToDtoMapper.examsPageToDtoPage(remainingExamsPage);

        // Wrap the Page<ExamDto> into PageDto<ExamDto> to return only necessary data
        return new PageDto<>(examsPageDto);
    }

    @Transactional(readOnly = true)
//    @Cacheable(value = "getAllExamsByAdminId",key = "#adminId")
    @Override
    public PageDto<ExamDto>getAllExamsByAdminId(Long adminId,Pageable pageable) {
        Page<ExamEntity> examEntitiesPage =examRepository.findAllByAdmin_AdminId(adminId,pageable);
        // Use the mapper to convert Page<ExamEntity> to Page<ExamDto>

        Page<ExamDto> examsPage = entityToDtoMapper.examsPageToDtoPage(examEntitiesPage);

        //map AdminDto to Page Dto to avoid serialization and return only data we need
        return new PageDto<>(examsPage);

    }
    @Transactional(readOnly = true)
//    @Cacheable(value = "getAllExamsTitle",key = "#adminId")
    @Override
    public List<ExamDropListDto>getAllExamsTitle(Long adminId) {

       List<ExamEntity> examEntities = examRepository.findAllByAdmin_AdminId(adminId);
        if (examEntities == null || examEntities.isEmpty()) {
            return Collections.emptyList();
        }

        return examEntities.stream().map(examEntity -> {
            ExamDropListDto dto = new ExamDropListDto();
            dto.setExamId(examEntity.getExamId());
            dto.setExamTitle(examEntity.getExamTitle());
            dto.setTotalQuestions(examRepository.countTotalQuestionsByExamId(examEntity.getExamId()));
            return dto;
        }).collect(Collectors.toList());

    }


    private List<QuestionEntity> getQuestionsForExam(String examTitle, int easy, int medium, int hard ) {
        List<QuestionEntity> filteredQuestions = questionRepositary.findByCategoryAndIsDeletedFalse(examTitle);
        Collections.shuffle(filteredQuestions);

        List<QuestionEntity> finalList = new ArrayList<>();
        int easyCount = 0, mediumCount = 0, hardCount = 0;

        for (QuestionEntity question : filteredQuestions) {
            switch (question.getDifficulty().toLowerCase()) {
                case "easy":
                    if (easyCount < easy) {
                        finalList.add(question);
                        easyCount++;
                    }
                    break;
                case "medium":
                    if (mediumCount < medium) {
                        finalList.add(question);
                        mediumCount++;
                    }
                    break;
                case "hard":
                    if (hardCount < hard) {
                        finalList.add(question);
                        hardCount++;
                    }
                    break;
            }
            if (easyCount >= easy &&
                    mediumCount >= medium &&
                    hardCount >= hard) {
                break;
            }
        }

        if (easyCount < easy || mediumCount < medium || hardCount < hard) {
            throw new ResourceNotFoundException("Not enough questions available to meet the requested criteria: \n" +
                    "Easy required: " + easy + ", found: " + easyCount + "; \n" +
                    "Medium required: " + medium + ", found: " + mediumCount + "; \n" +
                    "Hard required: " + hard + ", found: " + hardCount);
        }
        Collections.shuffle(finalList);
        return finalList;
    }



    /****************** Not Used ******************/

    //    @Override
//    public ExamDto addExam(AddExamRequest addExamRequest) {
//
//
//        if(!adminRepository.existsById(addExamRequest.getAdminId())) {
//            throw new ResourceNotFoundException("Admin does not exist");
//        }
//        AdminEntity admin = adminRepository.findById(addExamRequest.getAdminId()).get();
//
//
//
//
//        ExamEntity examEntity = new ExamEntity();
//
//        examEntity.setExamTitle(addExamRequest.getExamTitle());
//        examEntity.setExamDescription(addExamRequest.getExamDescription());
//        examEntity.setExamDuration(addExamRequest.getExamDuration());
//        examEntity.setEasy(addExamRequest.getEasy());
//        examEntity.setMedium(addExamRequest.getMedium());
//        examEntity.setHard(addExamRequest.getHard());
//        examEntity.setCreatedDate(new Timestamp(System.currentTimeMillis()));
//        examEntity.setAdmin(admin);
//
//        ExamEntity savedExam = examRepository.save(examEntity);
//
//
//        return entityToDtoMapper.examToDto(savedExam);
//    }

    //    @Override
//    public List<ExamDto>getAllExamsByAdminUsername(String username) {
//        List<ExamEntity>exams=examRepository.findAllByAdmin_AdminUserName(username);
//        return entityToDtoMapper.examsToDtoList(exams);
//
//    }


    //    public List<QuestionDto> getQuestionsForExam(AddExamRequest request) {
//        List<QuestionDto> filteredQuestions = questionRepositary.findByCategory(request.getExamTitle());
//        Collections.shuffle(filteredQuestions);
//        List<QuestionDto> easyQuestions = new ArrayList<>();
//        List<QuestionDto> mediumQuestions = new ArrayList<>();
//        List<QuestionDto> hardQuestions = new ArrayList<>();
//
//        for (QuestionDto question : filteredQuestions) {
//            switch (question.getDifficulty().toLowerCase()) {
//                case "easy":
//                    if (easyQuestions.size() < request.getEasy()) {
//                        easyQuestions.add(question);
//                    }
//                    break;
//                case "medium":
//                    if (mediumQuestions.size() < request.getMedium()) {
//                        mediumQuestions.add(question);
//                    }
//                    break;
//                case "hard":
//                    if (hardQuestions.size() < request.getHard()) {
//                        hardQuestions.add(question);
//                    }
//                    break;
//            }
//
//            if (easyQuestions.size() >= request.getEasy() &&
//                    mediumQuestions.size() >= request.getMedium() &&
//                    hardQuestions.size() >= request.getHard()) {
//                break;
//            }
//        }
//
//        List<QuestionDto> finalList = new ArrayList<>();
//        finalList.addAll(easyQuestions);
//        finalList.addAll(mediumQuestions);
//        finalList.addAll(hardQuestions);
//        Collections.shuffle(finalList);
//
//        return finalList;
//    }

//
//
//    @Transactional(readOnly = true)
//    @Cacheable(value = "getExamsByExamTitle",key = "#examTitle + '-' + #pageable.pageNumber")
//    @Override
//    public PageDto<ExamDto> getExamsByExamTitle(String examTitle, Pageable pageable) {
//
//        if(!examRepository.existsByExamTitle(examTitle)){
//            throw new ResourceNotFoundException("Exams with this "+examTitle+" does not exist");
//        }
//
//        //find exams by title and map whole of entity into page of exam entity
//        Page<ExamEntity> examEntitiesPage = examRepository.findAllByExamTitle(examTitle,pageable);
//
//        // Use the mapper to convert Page<ExamEntity> to Page<ExamDto>
//
//        Page<ExamDto> examsPage = entityToDtoMapper.examsPageToDtoPage(examEntitiesPage);
//
//        //map AdminDto to Page Dto to avoid serialization and return only data we need
//        return new PageDto<>(examsPage);
//
//    }



}
