package com.online_exam.examer.question;


import com.online_exam.examer.admin.AdminEntity;
import com.online_exam.examer.exam.ExamEntity;
import com.online_exam.examer.question.enums.QuestionType;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import java.util.List;

@Entity
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Table(indexes = {
        @Index(name = "idx_question_category", columnList = "category") // Index for category filtering
})
public class QuestionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "question_seq")
    @SequenceGenerator(name = "question_seq", sequenceName = "question_seq", allocationSize = 1)
    private long questionId;


    @Column(length = 1000)
    @NotNull(message = "Question content cannot be null")
    @Size(max = 1000, message = "Question content cannot exceed 1000 characters")
    private String questionContent;


    @NotNull(message = "Category cannot be null")
    private String category;

    @Enumerated(EnumType.STRING)
    @Column(name = "question_type")
    @NotNull(message = "Question type cannot be null")
    private QuestionType questionType;


//    @NotNull(message = "correct answer cannot be null")
//    private String correctAnswer;


//    @NotNull(message = "Option 1 cannot be null")
//    private String option1;
//    @NotNull(message = "Option 2 cannot be null")
//    private String option2;
//    @NotNull(message = "Option 3 cannot be null")
//    private String option3;
//    @NotNull(message = "Option 4 cannot be null")
//    private String option4;


    @NotNull(message = "Difficulty cannot be null")
    private String difficulty;

    @OneToMany(
            mappedBy = "question",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private List<QuestionOptionEntity> options;

    @ManyToOne()
    @JoinColumn(name = "adminId")
//    @NotNull(message = "Admin is required to assign the question")
    private AdminEntity admin;

    @ManyToMany(mappedBy = "assignedQuestions")
    private List<ExamEntity> exams;

//    @Column( nullable = true)
//    private boolean isDeleted;
    @Column(name = "is_deleted")
    private boolean isDeleted=false ;


}
