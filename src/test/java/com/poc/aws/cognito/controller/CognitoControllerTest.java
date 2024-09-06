package com.poc.aws.cognito.controller;

import com.poc.aws.cognito.service.CognitoService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import software.amazon.awssdk.services.cognitoidentity.model.NotAuthorizedException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class CognitoControllerTest {

    @Mock
    private CognitoService cognitoService;

    @InjectMocks
    private CognitoController cognitoController;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        mockMvc = MockMvcBuilders.standaloneSetup(cognitoController).build();
    }

    /*
    @Test
    void authenticateAndGetJWT_SuccessfulAuthentication() throws Exception {
        // Arrange
        String username = "testUser";
        String password = "testPassword";
        String expectedJwt = "testJWT";

        when(cognitoService.authenticateAndGetJWT(username, password)).thenReturn(expectedJwt);

        // Act & Assert
        mockMvc.perform(post("/cognito/auth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedJwt));
    }

    @Test
    void authenticateAndGetJWT_InvalidCredentials() throws Exception {
        when(cognitoService.authenticateAndGetJWT(anyString(), anyString())).thenThrow(NotAuthorizedException.class);

        mockMvc.perform(post("/cognito/auth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"invalidUser\",\"password\":\"invalidPassword\"}"))
                .andExpect(status().isUnauthorized());
    }
    */
}
