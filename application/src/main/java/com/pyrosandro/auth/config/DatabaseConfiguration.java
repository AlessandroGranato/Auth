package com.pyrosandro.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration
@EnableJpaRepositories({"com.pyrosandro.auth.repository"})
@EnableTransactionManagement
public class DatabaseConfiguration {
}
