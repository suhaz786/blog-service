package com.suhas.documentation.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger.web.ApiKeyVehicle;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Collections;

@Configuration
@EnableSwagger2
public class SwaggerConfig {
    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .useDefaultResponseMessages(false)
                .securitySchemes(
                        Collections.singletonList(
                                new ApiKey(HttpHeaders.AUTHORIZATION, HttpHeaders.AUTHORIZATION, ApiKeyVehicle.HEADER.getValue())
                        )
                )
                .securityContexts(
                        Collections.singletonList(
                                SecurityContext.builder().securityReferences(
                                        Collections.singletonList(
                                                new SecurityReference(HttpHeaders.AUTHORIZATION, new AuthorizationScope[0])
                                        )
                                ).build()
                        )
                )
                .apiInfo(SwaggerConfig.buildApiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.suhas"))
                .paths(PathSelectors.any())
                .build();
    }

    private static ApiInfo buildApiInfo() {
        return new ApiInfoBuilder()
                .title("Spring Boot REST based Blog Application")
                .description("RESTful API of a headless CMS.")
                .version("1.2.0")
                .contact(new Contact("Suhas Saheer", "", "suhaz786@gmail.com"))
                .build();
    }
}
