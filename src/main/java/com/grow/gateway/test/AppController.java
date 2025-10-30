package com.grow.gateway.test;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AppController {

    @Value("${spring.application.name}")
    private String appName;

    @Value("${server.port}")
    private String serverPort;

    @Value("${spring.profiles.active}")
    private String activeProfile;

    @GetMapping("/")
    public String test() {
        return "Hello, " + appName + " (" + serverPort + ") in " + activeProfile + " profile.";
    }
}
