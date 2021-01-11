package com.tistory.ospace.simplesecurity3.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {
    private static Logger LOGGER = LoggerFactory.getLogger(ApiController.class);
    
    @GetMapping("/me")
    public Object me(Authentication auth) {
        LOGGER.debug("me begin - auth[{}]", auth);
        return auth;
    }
}
