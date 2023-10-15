package com.pyrosandro.auth.service.impl;

import com.pyrosandro.auth.exception.AuthErrorConstants;
import com.pyrosandro.auth.exception.AuthException;
import com.pyrosandro.auth.model.RefreshToken;
import com.pyrosandro.auth.repository.AuthUserRepository;
import com.pyrosandro.auth.repository.RefreshTokenRepository;
import com.pyrosandro.auth.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    @Value("${auth.jwt-refresh-token-expiration-ms}")
    private Long jwtRefreshTokenExpirationMs;

    private final RefreshTokenRepository refreshTokenRepository;

    private final AuthUserRepository authUserRepository;

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByRefreshToken(token);
    }

    @Override
    public RefreshToken createRefreshToken(Long userId) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setAuthUser(authUserRepository.getById(userId));
        refreshToken.setRefreshToken(UUID.randomUUID().toString());
        refreshToken.setExpirationDate(LocalDateTime.now().plus(jwtRefreshTokenExpirationMs, ChronoUnit.MILLIS));
        log.info("refreshToken: {}", refreshToken.toString());
        refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }

    @Override
    @Transactional(dontRollbackOn = AuthException.class)
    public RefreshToken verifyExpiration(RefreshToken token) throws AuthException {
        if (token.getExpirationDate().compareTo(LocalDateTime.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new AuthException(AuthErrorConstants.EXPIRED_JWT_REFRESH_TOKEN, null);
        }
        return token;
    }

    @Override
    @Transactional
    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByAuthUser(authUserRepository.getById(userId));
    }
}
