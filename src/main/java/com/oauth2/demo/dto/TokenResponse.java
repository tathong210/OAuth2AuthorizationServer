package com.oauth2.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Service;

@NoArgsConstructor
@Getter
@Service
@Builder
@AllArgsConstructor
public class TokenResponse {
    private String access_token;
    private String refresh_token;
    private String token_type;
    private long expires_in;
}
