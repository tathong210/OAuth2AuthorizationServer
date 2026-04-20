package com.oauth2.demo.constant;

public enum CustomAuthorizationGrantType {
    PASSWORD("password");
    public final String value;

    CustomAuthorizationGrantType(String value) {
        this.value = value;
    }
}
