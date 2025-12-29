package com.online_exam.examer.user_answers;

import com.online_exam.examer.exam_submission.ExamSubmissionEntity;
import com.online_exam.examer.exam_submission.ExamSubmissionRepository;
import com.online_exam.examer.exception.ResourceNotFoundException;
import com.online_exam.examer.mapper.EntityToDtoMapper;
import com.online_exam.examer.question.QuestionEntity;
import com.online_exam.examer.question.QuestionOptionEntity;
import com.online_exam.examer.question.QuestionOptionRepository;
import com.online_exam.examer.question.QuestionRepository;
import com.online_exam.examer.user_answers.dto.UserAnswerViewDto;
import com.online_exam.examer.user_answers.request.UserAnswerSubmitRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserAnswerService implements IUserAnswerService {

    private final UserAnswerRepository userAnswerRepository;
    private final UserAnswerOptionRepository userAnswerOptionRepository;
    private final ExamSubmissionRepository examSubmissionRepository;
    private final QuestionRepository questionRepository;
    private final QuestionOptionRepository questionOptionRepository;
    private final EntityToDtoMapper entityToDtoMapper;

    @Override
    @Transactional
    public void submitAnswer(UserAnswerSubmitRequest request) {

        // 1️⃣ Fetch the exam submission
        ExamSubmissionEntity submission = examSubmissionRepository.findById(request.getExamSubmissionId())
                .orElseThrow(() -> new ResourceNotFoundException("Exam submission not found"));

        // 2️⃣ Loop through all question answers and save
        for (UserAnswerSubmitRequest.QuestionAnswer qa : request.getAnswers()) {

            QuestionEntity question = questionRepository.findById(qa.getQuestionId())
                    .orElseThrow(() -> new ResourceNotFoundException("Question not found"));

            UserAnswerEntity answer = new UserAnswerEntity();
            answer.setExamSubmission(submission);
            answer.setQuestion(question);
            answer.setWrittenAnswer(qa.getWrittenAnswer());
            answer.setCreatedDate(LocalDateTime.now());
            userAnswerRepository.save(answer);

            // Save selected MCQ options
            List<Long> selectedOptionIds = qa.getSelectedOptionIds();
            if (selectedOptionIds != null && !selectedOptionIds.isEmpty()) {
                List<UserAnswerOptionEntity> userAnswerOptions = new ArrayList<>();
                for (Long optionId : selectedOptionIds) {
                    QuestionOptionEntity option = questionOptionRepository.findById(optionId)
                            .orElseThrow(() -> new ResourceNotFoundException("Option not found"));
                    UserAnswerOptionEntity uao = new UserAnswerOptionEntity();
                    uao.setUserAnswer(answer);
                    uao.setOption(option);

                    // 🔥 THIS LINE FIXES THE SCORE
                    answer.getSelectedOptions().add(uao);

                    userAnswerOptions.add(uao);

                }
                //userAnswerOptionRepository.saveAll(userAnswerOptions);
            }
        }

        // 3️⃣ Calculate score in a separate method
        int totalScore = calculateScore(submission.getExamSubmissionId());

        // 4️⃣ Update exam submission
        submission.setScore(totalScore);
        submission.setStatus(true);
        examSubmissionRepository.save(submission);
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserAnswerViewDto> getAnswersBySubmission(Long examSubmissionId) {
        List<UserAnswerEntity> answers = userAnswerRepository.findByExamSubmission_ExamSubmissionId(examSubmissionId);
        return entityToDtoMapper.userAnswersToDtoList(answers);
    }

    @Override
    @Transactional(readOnly = true)
    public int calculateScore(Long examSubmissionId) {
        ExamSubmissionEntity submission = examSubmissionRepository.findById(examSubmissionId)
                .orElseThrow(() -> new ResourceNotFoundException("Exam submission not found"));

        int totalScore = 0;

        List<UserAnswerEntity> answers = userAnswerRepository.findByExamSubmission_ExamSubmissionId(examSubmissionId);

        for (UserAnswerEntity answer : answers) {
            List<UserAnswerOptionEntity> selectedOptions = answer.getSelectedOptions();

            if (!selectedOptions.isEmpty()) {
                List<QuestionOptionEntity> allOptions = answer.getQuestion().getOptions();
                boolean allCorrect = true;

                for (QuestionOptionEntity option : allOptions) {
                    if (option.getIsCorrect() && selectedOptions.stream().noneMatch(uo -> uo.getOption().getOptionId().equals(option.getOptionId()))) {
                        allCorrect = false;
                        break;
                    }
                }

                for (UserAnswerOptionEntity uo : selectedOptions) {
                    if (!uo.getOption().getIsCorrect()) {
                        allCorrect = false;
                        break;
                    }
                }

                if (allCorrect) totalScore += 1;
            }
        }

        return totalScore;
    }


    // Optional: implement your scoring logic here if needed
    // private int calculateScore(ExamSubmissionEntity submission) { ... }
}
