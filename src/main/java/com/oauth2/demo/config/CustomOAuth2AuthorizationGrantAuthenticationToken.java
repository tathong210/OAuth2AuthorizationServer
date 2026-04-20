package com.oauth2.demo.config;

import com.oauth2.demo.constant.CustomAuthorizationGrantType;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

@Getter
public class CustomOAuth2AuthorizationGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String username;
    private final String password;

    protected CustomOAuth2AuthorizationGrantAuthenticationToken(String username, String password,
                                                                Authentication clientPrincipal,
                                                                Map<String, Object> additionalParameters) {

        super(new AuthorizationGrantType(CustomAuthorizationGrantType.PASSWORD.value), clientPrincipal, additionalParameters);
        this.username = username;
        this.password = password;
    }
}
