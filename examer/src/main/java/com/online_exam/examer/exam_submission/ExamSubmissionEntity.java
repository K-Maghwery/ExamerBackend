package com.online_exam.examer.exam_submission;

import com.online_exam.examer.exam.ExamEntity;
import com.online_exam.examer.user.UserEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import java.sql.Timestamp;

@Entity
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Table( indexes = {
        @Index(name = "idx_exam_submission_user_id", columnList = "user_id"), // Index on user_id for faster filtering
        @Index(name = "idx_exam_submission_exam_id", columnList = "exam_id")  // Index on exam_id for faster filtering
})

public class ExamSubmissionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator =  "exam_sub_seq")
    @SequenceGenerator(name = "exam_sub_seq", sequenceName = "exam_sub_seq", allocationSize = 1)
    private Long examSubmissionId;
    @NotNull(message = "Score is required")
    @Min(value = 0, message = "Score cannot be negative")
    private int score;
    @NotNull(message = "Status is required")
    private boolean status;
    private Timestamp createdDate;

    @ManyToOne()
    @JoinColumn(name = "userId",nullable = false)
    @NotNull(message = "User ID is required")
    private UserEntity user;

    @ManyToOne()
    @JoinColumn(name = "examId",nullable = false)
    @NotNull(message = "Exam ID is required")
    private ExamEntity exam;
    //    @Column( nullable = true)

   // @Column(name = "is_deleted", nullable = false)
    private boolean isDeleted=false ;

}
