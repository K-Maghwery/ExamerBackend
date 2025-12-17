package com.online_exam.examer.securety;


import com.online_exam.examer.admin.AdminEntity;
import com.online_exam.examer.admin.AdminRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtService{

    private final AdminRepository adminRepository;

    private static String SECRET_KEY;

    public JwtService(AdminRepository adminRepository) {
        this.adminRepository = adminRepository;
        SECRET_KEY = generateSecretKey();
    }

    //Function generate secret key
    public String generateSecretKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating SecretKey", e);
        }
    }


    public String generateToken(String username) {
        AdminEntity admin = adminRepository.findByAdminUserName(username);

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", admin.getRole());
        claims.put("id", admin.getAdminId());


        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 12000 * 60 * 60))
                .signWith(getKey(), SignatureAlgorithm.HS256).compact();
    }

    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build().parseClaimsJws(token).getBody();
    }

    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction) {
        final Claims claims = extractAllClaims(token);
        return claimsTFunction.apply(claims);
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    public String extractUserName(String token) {
        // extract username from jwt token
        return extractClaims(token, Claims::getSubject);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }


    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public Date getExpiryFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getExpiration();
    }

    public String extractJti(String token) {
        return extractAllClaims(token).getId();
    }


}
