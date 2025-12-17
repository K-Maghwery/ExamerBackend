package com.online_exam.examer.exam;

import com.online_exam.examer.mapper.PageDto;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface IExamService {

    void addExam(AddExamRequest addExamRequest);
    PageDto<ExamDto> deleteExamById(Long examId, Pageable pageable);

   PageDto<ExamDto> getAllExamsByAdminId(Long adminId, Pageable pageable);
   List<ExamDropListDto> getAllExamsTitle(Long adminId);

    /****************** Not Used ******************/

    //PageDto<ExamDto> getExamsByExamTitle(String examTitle, Pageable pageable);
    //List<QuestionDto> getQuestionsForExam(AddExamRequest request);
    //List<ExamDto> getAllExamsByAdminUsername(String username);

}
