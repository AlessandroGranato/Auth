package com.pyrosandro.auth.repository;

import com.pyrosandro.auth.model.Resource;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ResourceRepository extends JpaRepository<Resource, Long> {

    Optional<Resource> findByResourcePath(String resourcePath);
}
