package com.oauth2.demo.config;

import com.oauth2.demo.constant.CustomAuthorizationGrantType;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;

import java.security.Principal;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            @Lazy AuthenticationManager authenticationManager) { // THÊM @Lazy Ở ĐÂY
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomOAuth2AuthorizationGrantAuthenticationToken customPasswordToken =
                (CustomOAuth2AuthorizationGrantAuthenticationToken) authentication;

        // 1. Xác thực username + password
        Authentication userAuth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        customPasswordToken.getUsername(),
                        customPasswordToken.getPassword()
                )
        );

        OAuth2ClientAuthenticationToken clientPrincipal = (OAuth2ClientAuthenticationToken) customPasswordToken.getPrincipal();
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        // 2. Tạo Authorization (framework sẽ xử lý lưu)
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(userAuth.getName())
                .authorizationGrantType(new AuthorizationGrantType(CustomAuthorizationGrantType.PASSWORD.value))
                .attribute(Principal.class.getName(), userAuth)
                .authorizedScopes(registeredClient.getScopes());

        // 3. Generate tokens (framework sẽ lo)
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userAuth)
                .authorization(authorizationBuilder.build())
                .authorizedScopes(registeredClient.getScopes())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(new AuthorizationGrantType(CustomAuthorizationGrantType.PASSWORD.value))
                .build();

        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                registeredClient.getScopes()
        );

        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2TokenContext refreshContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(userAuth)
                    .authorization(authorizationBuilder.build())
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .authorizationGrantType(new AuthorizationGrantType(CustomAuthorizationGrantType.PASSWORD.value))
                    .build();

            OAuth2Token generatedRefresh = tokenGenerator.generate(refreshContext);
            if (generatedRefresh != null) {
                refreshToken = new OAuth2RefreshToken(
                        generatedRefresh.getTokenValue(),
                        generatedRefresh.getIssuedAt(),
                        generatedRefresh.getExpiresAt()
                );
            }
        }

        OAuth2Authorization authorization = authorizationBuilder
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        authorizationService.save(authorization);
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomOAuth2AuthorizationGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
