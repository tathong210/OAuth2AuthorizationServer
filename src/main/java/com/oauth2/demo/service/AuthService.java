package com.oauth2.demo.service;

import com.oauth2.demo.dto.LoginRequest;
import com.oauth2.demo.dto.TokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final RegisteredClientRepository clientRepository;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final OAuth2AuthorizationService authorizationService;

    public TokenResponse authenticate(LoginRequest loginRequest, String clientId) {
        RegisteredClient registeredClient = clientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new AuthenticationCredentialsNotFoundException("Client not found");
        }
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(authentication.getName())
                .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                .attribute(Principal.class.getName(), authentication)
                // Quan trọng: lưu authorized scopes vào attribute (tránh NPE khi refresh)
                .authorizedScopes(registeredClient.getScopes());

        OAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorization(authorizationBuilder.build())   // tạm build để generate
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizedScopes(registeredClient.getScopes())
                .build();

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(accessTokenContext);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                registeredClient.getScopes());

        // 5. Sinh Refresh Token
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {

            OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(authentication)
                    .authorization(authorizationBuilder.build())
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();

            OAuth2Token generatedRefresh = this.tokenGenerator.generate(refreshTokenContext);

            if (generatedRefresh != null) {
                refreshToken = new OAuth2RefreshToken(
                        generatedRefresh.getTokenValue(),
                        generatedRefresh.getIssuedAt(),
                        generatedRefresh.getExpiresAt()
                );
            }
        }

        // 3. Tạo OAuth2 Authorization để quản lý phiên này
        OAuth2Authorization authorization = authorizationBuilder
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        this.authorizationService.save(authorization);

        // 3. Trả về cho Client
        return TokenResponse.builder()
                .access_token(accessToken.getTokenValue())
                .token_type("Bearer")
                .expires_in(3600)
                .refresh_token(refreshToken.getTokenValue())
                .build();
    }
}
