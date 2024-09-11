package com.poc.aws.cognito.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.apache.commons.lang3.StringUtils;
import javax.naming.AuthenticationException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.poc.aws.cognito.domain.ResponseDTO;
import com.poc.aws.cognito.domain.TokenDTO;
import com.poc.aws.cognito.util.AuthenticationHelper;

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
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderResponseMetadata;

@Slf4j
@Service
public class CognitoService {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CognitoService.class);

    private final CognitoIdentityClient cognitoIdentityClient;
    private final CognitoIdentityProviderClient cognitoIdentityProviderClient;

    @Value("${aws.cognito.user-pool}")
    private String userPool;

    @Value("${aws.cognito.client-id}")
    private String clientId;

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

    public TokenDTO authenticateUserTMPAndGetJWT(String username, String password) {

        /*
         * Reglas de negocio que me validan el usuario
         */
        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);

        TokenDTO tokenDTO = null;
        try {
            AuthenticationHelper authenticationHelper = new AuthenticationHelper(cognitoIdentityProviderClient, identityPoolId, clientId, userPool);
            CognitoIdentityProviderResponseMetadata cognitoIdentityProviderResponseMetadata = authenticationHelper.createOrUpdateUserFromAdmin(username, StringUtils.leftPad(password, 6, "0"));
            log.info("cognitoIdentityProviderResponseMetadata: {}", cognitoIdentityProviderResponseMetadata);
            AuthenticationResultType authenticationResultType = authenticationHelper.performSRPAuthentication(username, StringUtils.leftPad(password, 6, "0"));
            log.info("authenticationResultType: {}", authenticationResultType);

            tokenDTO = TokenDTO
                    .builder()
                    .accessToken(authenticationResultType.accessToken())
                    .idToken(authenticationResultType.idToken())
                    .refreshToken(authenticationResultType.refreshToken())
                    .expiresIn(authenticationResultType.expiresIn())
                    .build();
        } catch (Exception e) {
            log.error("Error Auth", e.getMessage());
        }
        return tokenDTO;
    }

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
//
//        GetCredentialsForIdentityResponse getCredentialsForIdentityResponse = cognitoIdentityClient
//                .getCredentialsForIdentity(credentialsRequest);
//
//        log.info("getOpenIdTokenResponse: {}", getCredentialsForIdentityResponse);
//        log.info("===========");

//        GetOpenIdTokenRequest getOpenIdTokenRequest = GetOpenIdTokenRequest
//                .builder()
//                .identityId(identityPoolId)
//                .logins(authParams)
//                .build();
//
//        GetOpenIdTokenResponse getOpenIdTokenResponse = cognitoIdentityClient
//                .getOpenIdToken(getOpenIdTokenRequest);
//
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

        AuthenticationHelper authenticationHelper = new AuthenticationHelper(cognitoIdentityProviderClient, identityPoolId, clientId, userPool);
        AuthenticationResultType authenticationResultType = authenticationHelper.performCustomAuthentication(username, StringUtils.leftPad(password, 6, "0"));
//        AuthenticationResultType authenticationAdminResultType = authenticationHelper.performSRPAdminAuthentication(username, StringUtils.leftPad(password, 6, "0"));
        log.info("authenticationResultType: {}", authenticationResultType);
//        log.info("authenticationResultType: {}", authenticationAdminResultType);
        log.info("===========");

//        InitiateAuthRequest initiateAuthRequest = InitiateAuthRequest.builder()
////                .authFlow(AuthFlowType.USER_SRP_AUTH)
////                .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
//                .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
//                .clientId(clientId)
////                .userPoolId(userPoolId)
//                .authParameters(authParams)
//                .build();
//
//        InitiateAuthResponse initiateAuthResponse = cognitoIdentityProviderClient
//                .initiateAuth(initiateAuthRequest);


//        AdminInitiateAuthRequest adminInitiateAuthRequest = AdminInitiateAuthRequest.builder()
//                .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
//                .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
//                .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
//                .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
//                .clientId(clientId)
//                .userPoolId(userPool)
//                .authParameters(authParams)
//                .build();

//        AdminInitiateAuthResponse adminInitiateAuthResponse = cognitoIdentityProviderClient
//                .adminInitiateAuth(adminInitiateAuthRequest);

//        log.info("adminInitiateAuthResponse: {}", adminInitiateAuthResponse.authenticationResult().idToken());
//        log.info("===========");
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
