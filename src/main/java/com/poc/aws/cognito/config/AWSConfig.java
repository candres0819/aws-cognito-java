package com.poc.aws.cognito.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentity.CognitoIdentityClient;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

import org.springframework.context.annotation.Configuration;

@Configuration
public class AWSConfig {

    @Value("${aws.profile}")
    private String awsProfile;

    @Value("${aws.region}")
    private String awsRegion;

    @Value("${aws.cognito.identity-pool-id}")
    private String identityPoolId;

    @Value("${aws.secret-manager.arn}")
    private String secretId;

    /*
    @Bean
    public AWSCognitoIdentityProvider awsCognitoIdentityProvider() {
        return AWSCognitoIdentityProviderClientBuilder.standard()
                .withCredentials(new ProfileCredentialsProvider(awsProfile))
                .withRegion(awsRegion)
                .build();
    }

    @Bean
    public AmazonCognitoIdentity getCognitoIdentityClient() {
        return AmazonCognitoIdentityClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(new AnonymousAWSCredentials()))
                .withRegion(awsRegion)
                .build();
    }

    @Bean
    public AWSSecretsManager getSecretsManagerClient() {
        return AWSSecretsManagerClientBuilder.standard()
                .withRegion(awsRegion)
                .build();
    }

    /*
    @Bean
    public Credentials getTemporaryCredentials() {
        AmazonCognitoIdentity cognitoIdentityClient = getCognitoIdentityClient();

        GetIdRequest getIdRequest = new GetIdRequest();
        getIdRequest.setIdentityPoolId(identityPoolId);
        GetIdResult getIdResult = cognitoIdentityClient.getId(getIdRequest);

        GetCredentialsForIdentityRequest getCredentialsRequest = new GetCredentialsForIdentityRequest();
        getCredentialsRequest.setIdentityId(getIdResult.getIdentityId());
        GetCredentialsForIdentityResult getCredentialsResult = cognitoIdentityClient.getCredentialsForIdentity(getCredentialsRequest);

        return getCredentialsResult.getCredentials();
    }
    */

    @Bean
    public CognitoIdentityClient cognitoIdentityClient() {
//        return CognitoIdentityClient
//                .builder()
//                .region(Region.of(awsRegion))
//                .build();

        return CognitoIdentityClient
                .builder()
                .credentialsProvider(ProfileCredentialsProvider.create(awsProfile))
                .region(Region.of(awsRegion))
                .build();
    }
    
    @Bean
    public CognitoIdentityProviderClient cognitoIdentityProviderClient() {
//        return CognitoIdentityProviderClient
//                .builder()
//                .region(Region.of(awsRegion))
//                .build();
        
        return CognitoIdentityProviderClient
                .builder()
                .credentialsProvider(ProfileCredentialsProvider.create(awsProfile))
                .region(Region.of(awsRegion))
                .build();
    }
}
