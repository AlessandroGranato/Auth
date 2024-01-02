package com.pyrosandro.auth.jwt;

import com.pyrosandro.auth.exception.AuthErrorConstants;
import com.pyrosandro.auth.exception.AuthException;
import com.pyrosandro.auth.utils.AuthConstants;
import com.pyrosandro.common.error.CommonException;
import com.pyrosandro.common.error.ErrorConstants;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.Locale;

@Component
@Slf4j
public class JwtUtils {

    public JwtUtils(@Value("${auth.jwt-secret}") String jwtSecret, @Value("${auth.jwt-access-token-expiration-ms}") Long jwtAccessTokenExpirationMs,  MessageSource messageSource) {
        this.jwtSecret = jwtSecret;
        this. jwtAccessTokenExpirationMs = jwtAccessTokenExpirationMs;
        this.messageSource = messageSource;
    }

    private final String jwtSecret;
    private final Long jwtAccessTokenExpirationMs;
    protected final MessageSource messageSource;

    public String generateJwtToken(Authentication authentication) {
        AuthUserDetails authUserPrincipal = (AuthUserDetails) authentication.getPrincipal();
        String jwtToken = null;
        try {
            jwtToken = Jwts.builder()
                    .setSubject(authUserPrincipal.getUsername())
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date().getTime() + jwtAccessTokenExpirationMs)))
                    .signWith(SignatureAlgorithm.HS512, jwtSecret)
                    .compact();
        } catch (Exception e) {
            log.error("Error while generating the token: {}", e.getMessage());
        }
        return jwtToken;
    }

    public String generateJwtTokenFromUsername(String username) {
        String jwtToken = null;
        try {
            jwtToken = Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date().getTime() + jwtAccessTokenExpirationMs)))
                    .signWith(SignatureAlgorithm.HS512, jwtSecret)
                    .compact();
        } catch (Exception e) {
            log.error("Error while generating the token: {}", e.getMessage());
        }
        return jwtToken;
    }

    public String getUsernameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }


    public boolean validateJwtToken(String authToken) throws AuthException {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            log.error( messageSource.getMessage(String.valueOf(AuthErrorConstants.INVALID_JWT_SIGNATURE.code), null, Locale.getDefault()));
            throw new AuthException(AuthErrorConstants.INVALID_JWT_SIGNATURE, null, HttpStatus.UNAUTHORIZED);
        } catch (MalformedJwtException e) {
            log.error( messageSource.getMessage(String.valueOf(AuthErrorConstants.MALFORMED_JWT.code), null, Locale.getDefault()));
            throw new AuthException(AuthErrorConstants.MALFORMED_JWT, null, HttpStatus.UNAUTHORIZED);
        } catch (ExpiredJwtException e) {
            log.error( messageSource.getMessage(String.valueOf(AuthErrorConstants.EXIPERD_JWT.code), null, Locale.getDefault()));
            throw new AuthException(AuthErrorConstants.EXIPERD_JWT, null, HttpStatus.UNAUTHORIZED);
        } catch (UnsupportedJwtException e) {
            log.error( messageSource.getMessage(String.valueOf(AuthErrorConstants.UNSUPPORTED_JWT.code), null, Locale.getDefault()));
            throw new AuthException(AuthErrorConstants.UNSUPPORTED_JWT, null, HttpStatus.UNAUTHORIZED);
        } catch (IllegalArgumentException e) {
            log.error( messageSource.getMessage(String.valueOf(AuthErrorConstants.ILLEGAL_JWT_ARGUMENT.code), null, Locale.getDefault()));
            throw new AuthException(AuthErrorConstants.ILLEGAL_JWT_ARGUMENT, null, HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            log.error( messageSource.getMessage(String.valueOf(ErrorConstants.GENERIC_ERROR.code), null, Locale.getDefault()));
            throw new CommonException(ErrorConstants.GENERIC_ERROR, null, e.getMessage(), e);
        }
    }

    public String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AuthConstants.AUTHORIZATION_HEADER);
        if(!StringUtils.hasText(headerAuth) || !headerAuth.startsWith(AuthConstants.BEARER)) {
            return null;
        }
        return headerAuth.substring(7);
    }
}
