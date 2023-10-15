package com.pyrosandro.auth.resource;

import com.pyrosandro.auth.dto.request.RefreshTokenRequestDTO;
import com.pyrosandro.auth.dto.request.SignInRequestDTO;
import com.pyrosandro.auth.dto.request.SignUpRequestDTO;
import com.pyrosandro.auth.dto.response.AuthorizeResourceResponseDTO;
import com.pyrosandro.auth.dto.response.JwtResponse;
import com.pyrosandro.auth.dto.response.MessageResponse;
import com.pyrosandro.auth.dto.response.RefreshTokenResponseDTO;
import com.pyrosandro.auth.exception.AuthErrorConstants;
import com.pyrosandro.auth.exception.AuthException;
import com.pyrosandro.auth.jwt.AuthUserDetails;
import com.pyrosandro.auth.jwt.JwtUtils;
import com.pyrosandro.auth.model.*;
import com.pyrosandro.auth.repository.AuthUserRepository;
import com.pyrosandro.auth.repository.ResourceRepository;
import com.pyrosandro.auth.repository.RoleRepository;
import com.pyrosandro.auth.service.RefreshTokenService;
import com.pyrosandro.auth.service.impl.AuthUserDetailsServiceImpl;
import com.pyrosandro.auth.utils.AuthConstants;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    AuthenticationManager authenticationManager;
    AuthUserRepository authUserRepository;
    RoleRepository roleRepository;
    PasswordEncoder encoder;
    JwtUtils jwtUtils;
    AuthUserDetailsServiceImpl authUserDetailsService;
    ResourceRepository resourceRepository;
    RefreshTokenService refreshTokenService;

    public AuthController(
            AuthenticationManager authenticationManager,
            AuthUserRepository authUserRepository,
            RoleRepository roleRepository,
            PasswordEncoder encoder,
            JwtUtils jwtUtils,
            AuthUserDetailsServiceImpl authUserDetailsService,
            ResourceRepository resourceRepository,
            RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.authUserRepository = authUserRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
        this.authUserDetailsService = authUserDetailsService;
        this.resourceRepository = resourceRepository;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequestDTO signUpRequestDTO) throws AuthException {
        if (authUserRepository.existsByUsername(signUpRequestDTO.getUsername())) {
            throw new AuthException(AuthErrorConstants.USERNAME_ALREADY_USED, null);
        }
        if (authUserRepository.existsByEmail(signUpRequestDTO.getEmail())) {
            throw new AuthException(AuthErrorConstants.EMAIL_ALREADY_USED, null);
        }

        Set<String> strRoles = signUpRequestDTO.getRoles();
        Set<Role> roles = new HashSet<>();
        try {
            if (strRoles == null) {
                Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: role not found"));
                roles.add(userRole);
            } else {

                strRoles.forEach(strRole -> {
                    switch (strRole) {
                        case "admin":
                            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(() -> new RuntimeException("Error: role not found"));
                            roles.add(adminRole);
                            break;
                        case "mod":
                            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR).orElseThrow(() -> new RuntimeException("Error: role not found"));
                            roles.add(modRole);
                            break;
                        default:
                            Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: role not found"));
                            roles.add(userRole);
                    }
                });
            }
        } catch (RuntimeException e) {
            throw new AuthException(AuthErrorConstants.ROLE_NOT_FOUND, null);
        }
        AuthUser authUser = new AuthUser();
        authUser.setUsername(signUpRequestDTO.getUsername());
        authUser.setEmail(signUpRequestDTO.getEmail());
        authUser.setPassword(encoder.encode(signUpRequestDTO.getPassword()));
        authUser.setRoles(roles);

        authUserRepository.save(authUser);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody SignInRequestDTO signInRequestDTO) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequestDTO.getUsername(), signInRequestDTO.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        AuthUserDetails authUserDetails = (AuthUserDetails) authentication.getPrincipal();
        List<String> roles = authUserDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(authUserDetails.getId());

        JwtResponse jwtResponse = JwtResponse.builder()
                .accessToken(jwt)
                .refreshToken(refreshToken.getRefreshToken())
                .id(authUserDetails.getId())
                .type("Bearer")
                .username(authUserDetails.getUsername())
                .email(authUserDetails.getEmail())
                .roles(roles).build();

        return ResponseEntity.ok(jwtResponse);

    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequestDTO refreshTokenRequestDTO) throws AuthException {
        Optional<RefreshToken> refreshToken = refreshTokenService.findByToken(refreshTokenRequestDTO.getRefreshToken());
        if(refreshToken.isEmpty()) {
            throw new AuthException(AuthErrorConstants.REFRESH_TOKEN_NOT_FOUND, null);
        }
        refreshTokenService.verifyExpiration(refreshToken.get());
        String jwtResponse = jwtUtils.generateJwtTokenFromUsername(refreshToken.get().getAuthUser().getUsername());
        RefreshTokenResponseDTO refreshTokenResponseDTO = new RefreshTokenResponseDTO(jwtResponse, refreshToken.get().getRefreshToken());
        return ResponseEntity.ok(refreshTokenResponseDTO);

    }

    @GetMapping("/authorize-resource")
    public ResponseEntity<?> authorizeResource(HttpServletRequest request) throws AuthException {

        String jwt = jwtUtils.parseJwt(request);
        if (jwt == null) {
            throw new AuthException(AuthErrorConstants.MISSING_AUTHORIZATION_HEADER, null);
        }
        jwtUtils.validateJwtToken(jwt);
        String username = jwtUtils.getUsernameFromJwtToken(jwt);
        AuthUserDetails authUserDetails;
        try {
            authUserDetails = (AuthUserDetails) authUserDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException ex) {
            throw new AuthException(AuthErrorConstants.USERNAME_NOT_FOUND, new Object[]{username});
        }

        List<String> roles = authUserDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        String generalizedResourcePath = generalizeResourcePath(request.getHeader(AuthConstants.RESOURCE_PATH_HEADER));
        Resource resource = resourceRepository.findByResourcePath(generalizedResourcePath).orElseThrow(() -> new AuthException(AuthErrorConstants.RESOURCE_NOT_FOUND, new Object[]{generalizedResourcePath}));

        boolean isAuthorized = isResourceAuthorized(roles, resource.getRoles().stream().map(r -> r.getName().name()).collect(Collectors.toList()));

        if (!isAuthorized) {
            throw new AuthException(AuthErrorConstants.RESOURCE_NOT_AUTHORIZED, new Object[]{username, generalizedResourcePath});
        }
        AuthorizeResourceResponseDTO authorizeResourceResponseDTO = AuthorizeResourceResponseDTO.builder()
                .userId(authUserDetails.getId())
                .roles(roles)
                .build();
        return ResponseEntity.ok(authorizeResourceResponseDTO);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteYourEntity(@PathVariable Long id) throws AuthException {
        Optional<AuthUser> authUser = authUserRepository.findById(id);
        if (authUser.isPresent()) {
            authUser.get().getRoles().clear();
            refreshTokenService.deleteByUserId(authUser.get().getId());
            authUserRepository.delete(authUser.get());
            return new ResponseEntity<>("Entity deleted successfully", HttpStatus.OK);
        } else {
            throw new AuthException(AuthErrorConstants.AUTH_USER_NOT_FOUND, null);
        }
    }


    private String generalizeResourcePath(String resourcePath) {
        Pattern pattern = Pattern.compile("\\{[^}]+\\}");
        Matcher matcher = pattern.matcher(resourcePath);
        return matcher.replaceAll("*");
    }


    private boolean isResourceAuthorized(List<String> userRoles, List<String> resourceRoles) {
        return userRoles.stream()
                .anyMatch(userRole -> resourceRoles.stream()
                        .anyMatch(userRole::equals));
    }

//    private boolean isResourceAuthorized(List<String> userRoles, List<String> resourceRoles) {
//        for (String userRole : userRoles) {
//            for (String resourceRole : resourceRoles) {
//                if (userRole.equals(resourceRole)) {
//                    return true;
//                }
//            }
//        }
//        return false;
//    }
}
