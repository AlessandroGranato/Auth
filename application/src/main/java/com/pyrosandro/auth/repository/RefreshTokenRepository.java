package com.pyrosandro.auth.repository;

import com.pyrosandro.auth.model.AuthUser;
import com.pyrosandro.auth.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByRefreshToken(String refreshToken);

    @Modifying
    int deleteByAuthUser(AuthUser authUser);
}
