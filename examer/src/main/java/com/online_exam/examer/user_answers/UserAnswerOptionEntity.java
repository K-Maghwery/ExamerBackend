package com.online_exam.examer.user_answers;
import com.online_exam.examer.question.QuestionOptionEntity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "user_answer_option_entity")
@IdClass(UserAnswerOptionId.class)
public class UserAnswerOptionEntity {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_answer_id", nullable = false)
    private UserAnswerEntity userAnswer;

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "option_id", nullable = false)
    private QuestionOptionEntity option;
}

