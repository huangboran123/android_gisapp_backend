package com.utum.mobilegis;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@SpringBootApplication
@EnableAuthorizationServer
@MapperScan("com.utum.mobilegis.mapper")
public class AndroidGisappBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(AndroidGisappBackendApplication.class, args);
    }

}
