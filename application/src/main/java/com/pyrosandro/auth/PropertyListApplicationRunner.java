package com.pyrosandro.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.stereotype.Component;

/*
    * This class is used to print all the properties loaded by Spring Boot.
 */

@Component
public class PropertyListApplicationRunner implements ApplicationRunner {

    private final ConfigurableEnvironment environment;

    @Autowired
    public PropertyListApplicationRunner(ConfigurableEnvironment environment) {
        this.environment = environment;
    }

    /*
    Remove comment if you want to see the properties at startup time
     */
    @Override
    public void run(ApplicationArguments args) {
        System.out.println("List of Properties:");
        for (PropertySource<?> propertySource : environment.getPropertySources()) {
            if (propertySource.getName().startsWith("applicationConfig")) {
                // Skip internal Spring Boot property sources
                continue;
            }

            System.out.println("Property Source: " + propertySource.getName());
            if (propertySource instanceof EnumerablePropertySource) {
                EnumerablePropertySource<?> enumerablePropertySource = (EnumerablePropertySource<?>) propertySource;
                for (String propertyName : enumerablePropertySource.getPropertyNames()) {
                    String propertyValue = enumerablePropertySource.getProperty(propertyName).toString();
                    System.out.println(propertyName + " = " + propertyValue);
                }
            }
        }
    }
}