package com.poc.aws.cognito.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {
        "aws.region=us-west-2",
        "aws.cognito.userPoolId=test-user-pool-id",
        "aws.cognito.clientId=test-client-id"
})
class AWSConfigTest {

    @Autowired
    private AWSConfig awsConfig;

    /*
    @Test
    void testAwsRegionConfiguration() {
        assertEquals("us-west-2", awsConfig.getRegion());
    }

    @Test
    void testCognitoUserPoolIdConfiguration() {
        assertEquals("test-user-pool-id", awsConfig.getUserPoolId());
    }

    @Test
    void testCognitoClientIdConfiguration() {
        assertEquals("test-client-id", awsConfig.getClientId());
    }
    */
}
