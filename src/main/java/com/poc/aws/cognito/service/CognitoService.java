package com.poc.aws.cognito.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import javax.naming.AuthenticationException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.poc.aws.cognito.domain.ResponseDTO;

import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentity.CognitoIdentityClient;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityResponse;
import software.amazon.awssdk.services.cognitoidentity.model.GetIdRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetIdResponse;
import software.amazon.awssdk.services.cognitoidentity.model.GetOpenIdTokenForDeveloperIdentityRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetOpenIdTokenForDeveloperIdentityResponse;
import software.amazon.awssdk.services.cognitoidentity.model.GetOpenIdTokenRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetOpenIdTokenResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;

@Slf4j
@Service
public class CognitoService {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CognitoService.class);

    private final CognitoIdentityClient cognitoIdentityClient;
    private final CognitoIdentityProviderClient cognitoIdentityProviderClient;

    //@Value("${aws.cognito.user-pool}")
    //private String userPool;

    //@Value("${aws.cognito.client-id}")
    //private String clientId;

    @Value("${aws.cognito.identity-pool-id}")
    private String identityPoolId;

    public CognitoService(CognitoIdentityClient cognitoIdentityClient, CognitoIdentityProviderClient cognitoIdentityProviderClient) {
        this.cognitoIdentityClient = cognitoIdentityClient;
        this.cognitoIdentityProviderClient = cognitoIdentityProviderClient;
    }

    /*
    public List<UserType> listUsers() {
        ListUsersRequest listUsersRequest = new ListUsersRequest().withUserPoolId(userPool);
        ListUsersResult listUsersResult = cognitoIdentityProvider.listUsers(listUsersRequest);
        return listUsersResult.getUsers();
    }

    public List<ProviderDescription> listIdentityProviders() {
        ListIdentityProvidersRequest listIdentityProvidersRequest = new ListIdentityProvidersRequest().withUserPoolId(userPool);
        ListIdentityProvidersResult listIdentityProvidersResult = cognitoIdentityProvider
                .listIdentityProviders(listIdentityProvidersRequest);
        return listIdentityProvidersResult.getProviders();
    }
    */

    public String authenticateAndGetJWT(String username, String password) {
        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);
        
        /*
         * AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
         *  .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
         *  .withUserPoolId(userPool)
         *  .withClientId(clientId)
         *  .withAuthParameters(authParams);
         *
         * AdminInitiateAuthResult authResult = cognitoIdentityProvider.adminInitiateAuth(authRequest);
         * AuthenticationResultType authenticationResult = authResult.getAuthenticationResult();
         * return authenticationResult.getIdToken();
         */

//        GetIdRequest idRequest = GetIdRequest
//                .builder()
//                .identityPoolId(identityPoolId)
//                .logins(authParams)
//                .build();
//
//        GetIdResponse idResponse = cognitoIdentityClient.getId(idRequest);
//
//        GetCredentialsForIdentityRequest credentialsRequest = GetCredentialsForIdentityRequest
//                .builder()
//                .identityId(idResponse.identityId())
//                .build();

//        GetCredentialsForIdentityResponse getCredentialsForIdentityResponse = cognitoIdentityClient
//                .getCredentialsForIdentity(credentialsRequest);

//        Map<String, String> logins = new HashMap<>();
//        logins.put("login.myapp.com", username);
//
//        GetOpenIdTokenRequest idRequest = GetOpenIdTokenRequest.builder()
//                .identityId(identityPoolId)
////                .logins(authParams)
//                .build();
//        GetOpenIdTokenResponse getOpenIdTokenResponse = cognitoIdentityClient
//                .getOpenIdToken(idRequest);
//        log.info("getOpenIdTokenResponse: {}", getOpenIdTokenResponse);
//        log.info("===========");
//
//        GetOpenIdTokenForDeveloperIdentityRequest request = GetOpenIdTokenForDeveloperIdentityRequest.builder()
//                .identityPoolId(identityPoolId)
////                .logins(authParams)
//                .build();
//
//        GetOpenIdTokenForDeveloperIdentityResponse getOpenIdTokenForDeveloperIdentityResponse = cognitoIdentityClient
//                .getOpenIdTokenForDeveloperIdentity(request);
//        log.info("getOpenIdTokenForDeveloperIdentityResponse: {}", getOpenIdTokenForDeveloperIdentityResponse);
//        log.info("===========");

        //return response.token();
        

        String clientId = "7d2c0aq3usq16bhclntspssmgb";
        String userPoolId = "us-east-1_434h91ehm";
        InitiateAuthRequest req = InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
//                .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                .clientId(clientId)
//                .userPoolId(userPoolId)
                .authParameters(authParams)
                .build();

        InitiateAuthResponse adminInitiateAuthResponse = cognitoIdentityProviderClient
                .initiateAuth(req);

        log.info("adminInitiateAuthResponse: {}", adminInitiateAuthResponse.authenticationResult().idToken());
        log.info("===========");
//        log.info("getCredentialsForIdentityResponse: {}", getCredentialsForIdentityResponse);
//        log.info("getCredentialsForIdentityResponse: {}", getCredentialsForIdentityResponse.credentials());
//        return getCredentialsForIdentityResponse.credentials().sessionToken();
        return "123";
    }

    /*
    @Override
    public ResponseEntity<ResponseDTO> revokeToken(String refreshToken, LogoutFormDto logoutFormDto, String tokenFirebase,
                                                   String deviceFirebase) {
        log.info("Init revokeToken {}", logoutFormDto.getDevice());

        // Iniciar proceso background para eliminar tokens firebase en db
        CompletableFuture<Boolean> tokenFirebaseRevoked = authenticationBusinessAsync.deleteTokenDevice(deviceFirebase);

        cognitoProvider.revokeTokenToRefreshToken(refreshToken);

        // Finaliza proceso background para crear o actualizar registro en db
        CompletableFuture.allOf(tokenFirebaseRevoked).join();

        boolean resultTokenFirebaseRevoked = false;
        if (tokenFirebaseRevoked.isDone()) {
            try {
                if (tokenFirebaseRevoked.get()) {
                    resultTokenFirebaseRevoked = tokenFirebaseRevoked.get();
                }
            } catch (InterruptedException e) {
                throw new AuthenticationException(HttpStatus.INTERNAL_SERVER_ERROR.value(), AuthenticationConstants.DAA000,
                        this.messagesUtil.getMessage(AuthenticationConstants.DAA000));
            } catch (ExecutionException e) {
                throw new AuthenticationException(HttpStatus.INTERNAL_SERVER_ERROR.value(), AuthenticationConstants.DAA000,
                        this.messagesUtil.getMessage(AuthenticationConstants.DAA000));
            }
        }

        try {
            cognitoProvider.refreshAccessToken(refreshToken);
        } catch (AuthenticationException ex) {
            if (ex.getCode().equals(AuthenticationConstants.DAA005)) {
                ResponseDto responseDto = new ResponseDto<>(HttpStatus.OK.value(), AuthenticationConstants.DAC004,
                        this.messagesUtil.getFormatedMessage(AuthenticationConstants.DAC004, resultTokenFirebaseRevoked));
                return new ResponseEntity<>(responseDto, HttpStatus.resolve(responseDto.getStatus()));
            }
        }
        throw new AuthenticationException(HttpStatus.INTERNAL_SERVER_ERROR.value(), AuthenticationConstants.DAA000,
                this.messagesUtil.getMessage(AuthenticationConstants.DAA000));
    }
    */
}
