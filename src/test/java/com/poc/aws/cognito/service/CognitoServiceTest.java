package com.poc.aws.cognito.service;

import com.poc.aws.cognito.config.AWSConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.services.cognitoidentity.CognitoIdentityClient;
import software.amazon.awssdk.services.cognitoidentity.model.NotAuthorizedException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class CognitoServiceTest {

    @Mock
    private CognitoIdentityClient cognitoClient;

    @Mock
    private AWSConfig awsConfig;

//    private CognitoService cognitoService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
//        cognitoService = new CognitoService(cognitoClient);
    }

    /*
    @Test
    void authenticateAndGetJWT_SuccessfulAuthentication() {
        // Arrange
        String username = "testUser";
        String password = "testPassword";
        String expectedJwt = "testJWT";

        AdminInitiateAuthResponse response = AdminInitiateAuthResponse.builder()
                .authenticationResult(AuthenticationResultType.builder()
                        .idToken(expectedJwt)
                        .build())
                .build();

        when(cognitoClient.adminInitiateAuth(any(AdminInitiateAuthRequest.class))).thenReturn(response);

        // Act
        String actualJwt = cognitoService.authenticateAndGetJWT(username, password);

        // Assert
        assertEquals(expectedJwt, actualJwt);
    }

    @Test
    void authenticateAndGetJWT_InvalidCredentials() {
        // Arrange
        String username = "invalidUser";
        String password = "invalidPassword";

        when(cognitoClient.adminInitiateAuth(any(AdminInitiateAuthRequest.class)))
                .thenThrow(NotAuthorizedException.class);

        // Act & Assert
        assertThrows(NotAuthorizedException.class, () -> cognitoService.authenticateAndGetJWT(username, password));
    }*/
}
