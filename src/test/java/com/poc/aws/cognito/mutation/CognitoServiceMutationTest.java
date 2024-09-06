package com.poc.aws.cognito.mutation;

import com.poc.aws.cognito.config.AWSConfig;
import com.poc.aws.cognito.service.CognitoService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.services.cognitoidentity.CognitoIdentityClient;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class CognitoServiceMutationTest {

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
    void authenticateAndGetJWT_MutationTest() {
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
        assertNotNull(actualJwt);
        assertFalse(actualJwt.isEmpty());
        assertEquals(expectedJwt, actualJwt);
    }
    */
}
