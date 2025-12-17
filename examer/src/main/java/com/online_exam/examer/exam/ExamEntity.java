package com.online_exam.examer.exam;

import com.online_exam.examer.admin.AdminEntity;
import com.online_exam.examer.exam_submission.ExamSubmissionEntity;
import com.online_exam.examer.question.QuestionEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import java.sql.Timestamp;
import java.util.List;

@Entity
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
//indexing
@Table(indexes = {
        @Index(name = "idx_exam_title", columnList = "examTitle"),
        @Index(name = "idx_exam_admin_id", columnList = "admin_id")

})

public class ExamEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator =  "exam_seq")
    @SequenceGenerator(name = "exam_seq", sequenceName = "exam_seq", allocationSize = 1)
    private Long examId;
    @Column(nullable = false)
    @NotNull(message = "Exam title is required")
    @Size(min = 1, max = 100, message = "Exam title must be between 1 and 100 characters")
    private String examTitle;
    @Size(max = 500, message = "Exam description must be at most 500 characters")
    private String examDescription;
    @NotNull(message = "Exam duration is required")
    @Min(value = 1, message = "Exam duration must be greater than 0 minutes")
    private int examDuration;
    @NotNull(message = "Easy question count is required")
    @Min(value = 0, message = "Easy question count cannot be negative")
    private int easy;
    @NotNull(message = "Medium question count is required")
    @Min(value = 0, message = "Medium question count cannot be negative")
    private int medium;
    @NotNull(message = "Hard question count is required")
    @Min(value = 0, message = "Hard question count cannot be negative")
    private int hard;
    private Timestamp createdDate;

    @OneToMany(mappedBy = "exam", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ExamSubmissionEntity> examSubmission;
    //indexing
    @ManyToOne()
    @JoinColumn(name = "adminId", nullable = false)
    @NotNull(message = "Admin ID is required")
    private AdminEntity admin;

    @ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(name = "question_exam",
            joinColumns = @JoinColumn(name = "exam_id"),
            inverseJoinColumns = @JoinColumn(name = "question_id"))
    private List<QuestionEntity> assignedQuestions;


    //        @Column( nullable = true)
    private boolean isDeleted=false ;

}
