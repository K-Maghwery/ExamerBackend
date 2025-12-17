package com.online_exam.examer.user;

import com.online_exam.examer.admin.AdminEntity;
import com.online_exam.examer.exam_submission.ExamSubmissionEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
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
        @Index(name = "idx_user_admin_id", columnList = "admin_id"),  // Index on adminId
})

public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator =  "user_seq")
    @SequenceGenerator(name = "user_seq", sequenceName = "user_seq", allocationSize = 1)
    private Long userId;
    @Column(nullable = false)
    @NotBlank(message = "Username is required.")
    @Pattern(regexp = "^[a-zA-Z_]{1,20}$", message = "Username must be 1-20 alphanumeric characters or underscores only.")
    private String userName;
    @NotEmpty(message = "Phone number cannot be empty")
    @Pattern(regexp = "^(012|011|015|010)\\d{8}$", message = "Phone number must start with 010, 011, 012, or 015 and be followed by 8 digits")
    private String phone;
    @Column(nullable = false)
    @NotEmpty(message = "Email cannot be empty")
    @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Email must be valid")
    private String email;

    @ManyToOne()
    @JoinColumn(name = "adminId",nullable = false)
    private AdminEntity admin;

    @OneToMany(mappedBy = "user" ,cascade = CascadeType.ALL)
    private List<ExamSubmissionEntity> examSubmission;
//        @Column( nullable = true)
    private boolean isDeleted=false ;

}
