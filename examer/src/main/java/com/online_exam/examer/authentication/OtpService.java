package com.online_exam.examer.authentication;

import com.online_exam.examer.admin.AdminEntity;
import com.online_exam.examer.admin.AdminRepository;
import com.online_exam.examer.exception.InvalidOtpException;
import com.online_exam.examer.exception.ResourceNotFoundException;
import com.online_exam.examer.user.UserRepository;
import com.online_exam.examer.util.EncryptionUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.*;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final AdminRepository adminRepository;
    private final EncryptionUtil encryptionUtil;

    public String generateOtp(String email) {

        if(!adminRepository.existsByEmail(email)||adminRepository.existsByEmailAndIsDeletedTrue(email)) {
            throw new ResourceNotFoundException("Email does not exist");
        }

        String otp = String.format("%04d", new Random().nextInt(9999)); // Generate 4-digit OTP
        AdminEntity admin = adminRepository.findByEmail(email);
        admin.setOtp(encryptionUtil.encryptOtp(otp));
        admin.setOtpExpiryDate(new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000));
        admin.setVerified(false);
        adminRepository.save(admin);


        return otp;
    }

    public void validateOtp(String email, String otp) {
        AdminEntity admin = adminRepository.findByEmail(email);
        if (otp.equals(encryptionUtil.decryptOtp(admin.getOtp())) && admin.getOtpExpiryDate().after(new Timestamp(System.currentTimeMillis()))) {
           // validatedEmails.add(email); // Mark email as validated
            admin.setOtp(null);
            admin.setVerified(true);
            adminRepository.save(admin);
        } else {
            admin.setVerified(false);
            adminRepository.save(admin);
            throw new InvalidOtpException("Invalid OTP");
        }
    }


    public boolean isOtpValidated(String email) {
        AdminEntity admin = adminRepository.findByEmail(email);
        //return validatedEmails.contains(email); // Check if OTP was validated
        return admin.isVerified();
    }

    public void clearValidation(String email) {
        //validatedEmails.remove(email); // Clear validation after successful password reset

        AdminEntity admin = adminRepository.findByEmail(email);
        admin.setVerified(false);
        adminRepository.save(admin);
    }
}