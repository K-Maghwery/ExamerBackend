package com.online_exam.examer.question;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;

@Entity
@Table(name = "question_option_entity")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class QuestionOptionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "option_seq")
    @SequenceGenerator(name = "option_seq", sequenceName = "option_seq", allocationSize = 1)
    @Column(name = "option_id")
    private Long optionId;

    @NotBlank(message = "Option text cannot be empty")
    @Column(name = "option_text", nullable = false, length = 255)
    private String optionText;

    @NotNull(message = "Option correctness must be specified")
    @Column(name = "is_correct", nullable = false)
    private Boolean isCorrect;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "question_id", nullable = false)
    private QuestionEntity question;
}
