package com.online_exam.examer.admin;

import com.online_exam.examer.exam.ExamEntity;
import com.online_exam.examer.question.QuestionEntity;
import com.online_exam.examer.user.UserEntity;
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

import java.sql.Timestamp;
import java.util.List;

@Entity
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
//indexing
@Table( indexes = {
        @Index(name = "idx_admin_username", columnList = "adminUserName"),
        @Index(name = "idx_admin_email", columnList = "email"),
        @Index(name = "idx_admin_role", columnList = "role")
})

public class AdminEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator =  "admin_seq")
    @SequenceGenerator(name = "admin_seq", sequenceName = "admin_seq", allocationSize = 1)
    private Long adminId;
    //indexing
    @Column(nullable = false, unique = true)
    @NotBlank(message = "Admin username is required.")
    @Pattern(regexp = "^[a-zA-Z0-9_]{1,20}$", message = "Username must be 1-20 alphanumeric characters or underscores only.")
    private String adminUserName;
    @NotEmpty(message = "Phone number cannot be empty")
    @Pattern(regexp = "^(012|011|015|010)\\d{8}$", message = "Phone number must start with 010, 011, 012, or 015 and be followed by 8 digits")
    private String phone;
    //indexing
    @Column(nullable = false, unique = true)
    @NotEmpty(message = "Email cannot be empty")
    @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Email must be valid")
    private String email;
    private String password;
    private String role;
    private String otp;
//    @Column(nullable = true)
    private boolean isVerified;

    private Timestamp otpExpiryDate;

    @OneToMany(mappedBy = "admin", cascade = CascadeType.ALL)
    private List<UserEntity> user;

    @OneToMany(mappedBy = "admin", cascade = CascadeType.ALL)
    private List<ExamEntity> exam;

    //for super admin we need to try handel admin and superadmin with dto
    @OneToMany(mappedBy = "admin", cascade = CascadeType.ALL)
    private List<QuestionEntity> question;


//    update admin_entity set is_deleted=false;
//    @Column( nullable = true)
    private boolean isDeleted=false ;
}
