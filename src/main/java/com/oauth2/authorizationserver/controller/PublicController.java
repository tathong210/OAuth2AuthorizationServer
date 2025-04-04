package com.oauth2.authorizationserver.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class PublicController {
    @GetMapping("/hello")
    ResponseEntity<String> hello() {
        return ResponseEntity.ok("hello");
    }

    @GetMapping("/demo")
    ResponseEntity<String> demo() {
        return ResponseEntity.ok("Hello, this is OAuth 2.1 Authorization Server");
    }
}
