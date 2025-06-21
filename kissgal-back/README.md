# KissGal Backend

Backend service for the KissGal application built with Spring Boot.

## Description

KissGal Backend is a secure Spring Boot application that provides REST API services with OAuth2 authentication and PostgreSQL database integration.

## Technologies

- **Java Version:** 21
- **Framework:** Spring Boot 3.4.6
- **Database:** PostgreSQL
- **Database Migration:** Liquibase
- **Security:** Spring Security with OAuth2
- **Documentation:** OpenAPI (Swagger)
- **Testing:**
    - JUnit 5
    - ArchUnit
    - Embedded PostgreSQL (Zonky)
    - JaCoCo for test coverage

## Features

- OAuth2 Resource Server and Client support
- RESTful API endpoints
- PostgreSQL database integration with Liquibase migrations
- Swagger UI for [API documentation](http://localhost:8080/swagger-ui.html)
- Actuator endpoints for monitoring
- Comprehensive testing setup with both unit and integration tests

The project includes:
- Formatter Maven Plugin for consistent code styling
- ArchUnit for architectural testing
- Comprehensive test coverage reporting with JaCoCo

## Building the Project

The project uses Maven for build management. Here are some common commands:

```bash
# Build the project
mvn clean install
# The application is packaged as a Spring Boot JAR with the name `kissgal-back.jar`.
# To run the application:
java -jar target/kissgal-back.jar
# Run unit tests
mvn test
# Skip unit tests
mvn clean verify -Dskip.ut=true
# Run integration tests
mvn verify
# Skip integration tests
mvn verify -Dskip.it=true
```
