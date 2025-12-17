package com.online_exam.examer.securety;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtCleanupScheduler {

    private final JwtBlacklistRepository jwtBlacklistRepository;

    // Run every hour (3600000 ms)
//    @Scheduled(fixedRate = 3600000)
    @Scheduled(cron = "0 0 3 ? * FRI", zone = "Europe/Istanbul")
    @Transactional
    public void cleanExpiredTokens() {
        jwtBlacklistRepository.deleteByExpiryDateBefore(new Date());
    }
}
