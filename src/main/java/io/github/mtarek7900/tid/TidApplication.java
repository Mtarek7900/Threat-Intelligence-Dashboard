package io.github.mtarek7900.tid;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class TidApplication {

    public static void main(String[] args) {
        SpringApplication.run(TidApplication.class, args);
    }
}
