package com.pyrosandro.auth.service;

import com.pyrosandro.auth.jwt.AuthUserDetails;
import com.pyrosandro.auth.model.AuthUser;
import com.pyrosandro.auth.repository.AuthUserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
public class AuthUserDetailsServiceImpl implements UserDetailsService {

    AuthUserRepository authUserRepository;

    public AuthUserDetailsServiceImpl(AuthUserRepository authUserRepository) {
        this.authUserRepository = authUserRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser authUser = authUserRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
        return AuthUserDetails.build(authUser);
    }
}
