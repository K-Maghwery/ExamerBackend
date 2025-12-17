package com.online_exam.examer.securety;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Entity
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class JwtBlacklist {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator =  "otp_seq")
    @SequenceGenerator(name = "otp_seq", sequenceName = "otp_seq", allocationSize = 1)
    private Long otpId;

    @Column(name = "token", nullable = false, unique = true, length = 1000)
    private String token;

    @Column(name = "expiry_date", nullable = false)
    private Date expiryDate;


    public JwtBlacklist(String token, Date expiryDate) {
        this.token = token;
        this.expiryDate = expiryDate;
    }

}