package com.pyrosandro.auth.service;


import com.pyrosandro.auth.exception.AuthException;
import com.pyrosandro.auth.model.RefreshToken;

import java.util.Optional;

public interface RefreshTokenService {

    Optional<RefreshToken> findByToken(String token);
    RefreshToken createRefreshToken(Long userId);
    RefreshToken verifyExpiration(RefreshToken token) throws AuthException;
    int deleteByUserId(Long userId);
}
