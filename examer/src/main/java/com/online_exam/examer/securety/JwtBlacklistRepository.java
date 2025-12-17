package com.online_exam.examer.securety;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Date;
import java.util.Optional;

public interface JwtBlacklistRepository extends JpaRepository<JwtBlacklist, Long> {
    Optional<JwtBlacklist> findByToken(String token);
    void deleteByExpiryDateBefore(Date now);
}