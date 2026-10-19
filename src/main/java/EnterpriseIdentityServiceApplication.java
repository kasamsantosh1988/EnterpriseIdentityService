package com.vam.eis;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class EnterpriseIdentityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(EnterpriseIdentityServiceApplication.class, args);
    }

}
