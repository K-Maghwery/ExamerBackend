package com.online_exam.examer.authentication;

import com.online_exam.examer.admin.*;
import com.online_exam.examer.admin.request.*;
import com.online_exam.examer.exception.ResourceNotFoundException;
import com.online_exam.examer.response.GeneralResponse;
import com.online_exam.examer.response.LoginResponse;
import com.online_exam.examer.securety.JwtBlacklistService;
import com.online_exam.examer.securety.JwtService;
import com.online_exam.examer.user.request.UserContactRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.Date;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final OtpService otpService;
    private final EmailService emailService;
    private final AdminService adminService;
    private final JwtBlacklistService jwtBlacklistService;




    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginAdminRequest loginAdminRequest) {

        if(adminService.isAdminDeleted(loginAdminRequest.getAdminUserName()))
        {
            throw new ResourceNotFoundException("Admin does not exist");
        }

        authenticationManager.authenticate
                (new UsernamePasswordAuthenticationToken(loginAdminRequest.getAdminUserName(), loginAdminRequest.getPassword()));

        return ResponseEntity.status(HttpStatus.OK).
                body(new LoginResponse("Login Successfully",jwtService.generateToken(loginAdminRequest.getAdminUserName())));

    }

    @PostMapping("/forgotPassword")
    public ResponseEntity<GeneralResponse> forgotPassword(@RequestBody ForgetPasswordRequest forgetPasswordRequest) {
        String otp = otpService.generateOtp(forgetPasswordRequest.getEmail()); // Generate OTP
        emailService.sendOtpEmail(forgetPasswordRequest.getEmail(), otp); // Send OTP to email
        return ResponseEntity.status(HttpStatus.OK).
                body(new GeneralResponse("OTP has been sent to your email"));
    }

    @PostMapping("/resetPasswordCheckOtp")
    public ResponseEntity<GeneralResponse> resetPasswordCheck(@RequestBody ResetPasswordRequest resetPasswordRequest) {
        otpService.validateOtp(resetPasswordRequest.getAdminEmail(), resetPasswordRequest.getOtpCode());
        return ResponseEntity.status(HttpStatus.OK).body(new GeneralResponse("OTP Matched"));
    }

    @PutMapping ("/resetPasswordUpdate")
    public ResponseEntity<GeneralResponse> resetPasswordUpdate(@RequestBody UpdateForgetPasswordRequest updateForgetPasswordRequest) {
        if (!otpService.isOtpValidated(updateForgetPasswordRequest.getAdminEmail())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new GeneralResponse("OTP is invalid"));
        }

        adminService.updatePassword(updateForgetPasswordRequest.getAdminEmail(), updateForgetPasswordRequest.getNewPassword());
        otpService.clearValidation(updateForgetPasswordRequest.getAdminEmail()); // Clear validation status after reset

        return ResponseEntity.status(HttpStatus.OK).body(new GeneralResponse("Password has been reset successfully"));
    }

    @PostMapping("/contact")
    public ResponseEntity<GeneralResponse> sendUserMessage(@RequestBody UserContactRequest userContactRequest) {
        emailService.sendContactEmail(userContactRequest.getUserEmail(), userContactRequest.getSubject(), userContactRequest.getUserMessage()); // Send OTP to email
        return ResponseEntity.status(HttpStatus.OK).body(new GeneralResponse("Your mail has been sent to our support team"));
    }
// before jti
//    @PostMapping("/logoutAdmin")
//    public ResponseEntity<GeneralResponse> logout(@RequestBody LogoutAdminRequest logoutAdminRequest) {
//
//        if (logoutAdminRequest.getToken() == null || logoutAdminRequest.getToken().isBlank()) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new GeneralResponse("Token is missing or invalid"));
//        }
//
//        try {
//            Date expiryDate = jwtService.getExpiryFromToken(logoutAdminRequest.getToken()); // Extract expiry as Date
//            jwtBlacklistService.addToBlacklist(logoutAdminRequest.getToken(), expiryDate);
//            return ResponseEntity.status(HttpStatus.OK).body(new GeneralResponse("Logged out successfully"));
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new GeneralResponse("Invalid token"));
//        }
//    }

    //after jti
    @PostMapping("/logoutAdmin")
    public ResponseEntity<GeneralResponse> logout(@RequestBody LogoutAdminRequest logoutAdminRequest) {
        String token = logoutAdminRequest.getToken();

        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().body(new GeneralResponse("Token is missing or invalid"));
        }

        try {
            String jti = jwtService.extractJti(token);
            Date expiry = jwtService.getExpiryFromToken(token);
            jwtBlacklistService.addToBlacklist(jti, expiry); // save jti only
            return ResponseEntity.ok(new GeneralResponse("Logged out successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new GeneralResponse("Invalid token"));
        }
    }





}
