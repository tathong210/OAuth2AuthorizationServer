package com.oauth2.demo.controller;


import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DemoController {

    // API này ai cũng gọi được
    @GetMapping("/public/hello")
    public String publicApi() {
        return "Chào bạn, đây là API công khai!";
    }

    // API này bị Resource Server bảo vệ, phải có Bearer Token
    @GetMapping("/me")
    public String protectedApi(Authentication authentication) {
        // authentication.getName() sẽ in ra "my-client-id" (nếu dùng client_credentials)
        // hoặc in ra "admin" (nếu user đăng nhập bằng mật khẩu)
        return "Chào " + authentication.getName() + "! Bạn đã truy cập thành công vào API bảo mật trên chính Auth Server.";
    }
}