package com.poc.aws.cognito.domain;

import java.io.Serializable;

public class AuthenticationRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private String username;
    private String password;

    public AuthenticationRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
