package com.oauth2.demo.controller;

import com.oauth2.demo.dto.LoginRequest;
import com.oauth2.demo.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;

    @PostMapping(value = "/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest,
                                   @RequestHeader(value = "X-Client-Id") String clientId) {
        return ResponseEntity.ok(authService.authenticate(loginRequest, clientId));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody LoginRequest loginRequest,
                                          HttpServletRequest request,
                                          HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            // Thiết lập SecurityContext
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            // LƯU SESSION: Đây là chìa khóa để SSO hoạt động
            new HttpSessionSecurityContextRepository().saveContext(context, request, response);

            Map<String, Object> map = new HashMap<>();
            map.put("message", "Authenticated successfully");
            return ResponseEntity.ok(map);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(401).body("Login failed");
        }
    }
}
