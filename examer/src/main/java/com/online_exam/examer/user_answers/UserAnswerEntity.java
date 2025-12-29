package com.online_exam.examer.user_answers;
import com.online_exam.examer.exam_submission.ExamSubmissionEntity;
import com.online_exam.examer.question.QuestionEntity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Table(
        name = "user_answer_entity",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"exam_submission_id", "question_id"})
        }
)

public class UserAnswerEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_answer_id")
    private Long userAnswerId;

    // 🔗 Exam submission
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "exam_submission_id", nullable = false)
    private ExamSubmissionEntity examSubmission;

    // 🔗 Question
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "question_id", nullable = false)
    private QuestionEntity question;

    // ✍ WRITTEN answer only
    @Column(name = "written_answer", columnDefinition = "TEXT")
    private String writtenAnswer;

    @CreationTimestamp
    @Column(name = "created_date")
    private LocalDateTime createdDate;

    // 🔗 Selected options (MCQ / TF)
    @OneToMany(mappedBy = "userAnswer", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<UserAnswerOptionEntity> selectedOptions = new ArrayList<>();
}
