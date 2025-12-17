package com.online_exam.examer.securety;

import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JwtBlacklistService {

    private final JwtBlacklistRepository blacklistRepository;

    public JwtBlacklistService(JwtBlacklistRepository blacklistRepository) {
        this.blacklistRepository = blacklistRepository;
    }

    /**
     * Adds the token to the blacklist.
     */
    public void addToBlacklist(String token, Date expiryDate) {
        if (expiryDate.after(new Date())) {
            blacklistRepository.save(new JwtBlacklist(token, expiryDate));
        }
    }

    /**
     * Checks if a token is blacklisted.
     */
    public boolean isBlacklisted(String token) {
        return blacklistRepository.findByToken(token)
                .filter(b -> b.getExpiryDate().after(new Date()))
                .isPresent();
    }

    /**
     * (Optional) Scheduled cleanup to remove expired tokens.
     */
    // @Scheduled(cron = "0 0 * * * *") // Every hour
    public void cleanupExpiredTokens() {
        blacklistRepository.findAll().stream()
                .filter(token -> token.getExpiryDate().before(new Date()))
                .forEach(blacklistRepository::delete);
    }
}