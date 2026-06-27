package com.infovergne.kissgal.webapp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "application.cors")
public record CorsConfig(String[] allowedOrigins, String[] allowedMethods, String[] allowedHeaders, boolean allowedCredentials, Integer maxAge){}