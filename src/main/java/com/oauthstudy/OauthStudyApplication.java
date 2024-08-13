package com.oauthstudy;

import com.oauthstudy.config.properties.AppProperties;
import com.oauthstudy.config.properties.CorsProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({
        CorsProperties.class,
        AppProperties.class
})
public class OauthStudyApplication {

    public static void main(String[] args) {
        SpringApplication.run(OauthStudyApplication.class, args);
    }

}
