package com.poc.aws.cognito.mutation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.poc.aws.cognito.controller.CognitoController;
import com.poc.aws.cognito.domain.AuthenticationRequest;
import com.poc.aws.cognito.service.CognitoService;

class CognitoControllerMutationTest {

    @Mock
    private CognitoService cognitoService;

    @InjectMocks
    private CognitoController cognitoController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void authenticateAndGetJWT_MutationTest() {
        // Arrange
        String username = "testUser";
        String password = "testPassword";
        String expectedJwt = "testJWT";

        // TokenDTO tokenDTO = TokenDTO
        // .builder()
        // .accessToken(expectedJwt)
        // .idToken("")
        // .refreshToken("")
        // .expiresIn(""
        // .build();

        when(cognitoService.authenticateAndGetJWT(anyString(), anyString())).thenReturn(expectedJwt);

        // Act
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(username, password);
        ResponseEntity<String> response = cognitoController.authenticateUserCustom(authenticationRequest);

        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(expectedJwt, response.getBody());

        // Additional assertions to catch potential mutations
        assertFalse(response.getBody().isEmpty());
        assertTrue(response.getBody().length() > 0);
        assertNotEquals("", response.getBody());
    }
}
