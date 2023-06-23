package com.pyrosandro.auth.jwt;

import com.pyrosandro.auth.exception.AuthException;
import com.pyrosandro.auth.utils.AuthConstants;
import com.pyrosandro.auth.utils.ErrorConstants;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@Component
@Slf4j
public class JwtUtils {

    @Value("${auth.jwt-secret}")
    private String jwtSecret;

    @Value("${auth.jwt-expiration-ms}")
    private Long jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        AuthUserDetails authUserPrincipal = (AuthUserDetails) authentication.getPrincipal();
        String jwtToken = null;
        try {
            jwtToken = Jwts.builder()
                    .setSubject(authUserPrincipal.getUsername())
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date().getTime() + jwtExpirationMs)))
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
            throw new AuthException(ErrorConstants.INVALID_JWT_SIGNATURE, null);
        } catch (MalformedJwtException e) {
            throw new AuthException(ErrorConstants.MALFORMED_JWT, null);
        } catch (ExpiredJwtException e) {
            throw new AuthException(ErrorConstants.EXIPERD_JWT, null);
        } catch (UnsupportedJwtException e) {
            throw new AuthException(ErrorConstants.UNSUPPORTED_JWT, null);
        } catch (IllegalArgumentException e) {
            throw new AuthException(ErrorConstants.ILLEGAL_ARGUMENT, null);
        } catch (Exception e) {
            throw new AuthException(ErrorConstants.GENERIC_ERROR, null, e.getMessage(), e);
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
