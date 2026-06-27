package com.infovergne.kissgal;

import com.infovergne.kissgal.webapp.config.CorsConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(CorsConfig.class)
public class KissgalBackApplication {

    public static void main(String[] args) {
        SpringApplication.run(KissgalBackApplication.class, args);
    }

}
