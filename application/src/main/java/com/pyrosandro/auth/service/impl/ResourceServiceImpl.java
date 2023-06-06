package com.pyrosandro.auth.service.impl;

import com.pyrosandro.auth.repository.ResourceRepository;
import com.pyrosandro.auth.service.ResourceService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class ResourceServiceImpl implements ResourceService {

    private ResourceRepository resourceRepository;

    public void authorizeResource() {
        //TODO - bring here the login in AuthController::authorizeResource method
    }
}
