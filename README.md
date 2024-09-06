# Spring Boot AWS Cognito Integration

This project demonstrates the seamless integration of AWS Cognito with a Spring Boot application. It provides a robust authentication and user management system leveraging AWS Cognito's powerful features.

## Features

- User Management:
  - List all Cognito users in the user pool
  - Retrieve detailed user information
- Identity Provider Integration:
  - List all configured identity providers
  - Support for social and enterprise identity providers
- Authentication:
  - Authenticate users against Cognito user pool
  - Obtain and validate JWT tokens
- Security:
  - Implement secure password policies
  - Enable multi-factor authentication (MFA)

## Prerequisites

Before you begin, ensure you have the following:

- Java Development Kit (JDK) 11 or later
- Maven 3.6 or later
- An AWS account with Cognito user pool set up
- AWS CLI configured with appropriate credentials
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/spring-boot-aws-cognito.git
   cd spring-boot-aws-cognito
   ```

2. Update `src/main/resources/application.properties` with your AWS Cognito details (see Configuration section)

3. Build the project:
   ```
   mvn clean install
   ```

4. Run the application:
   ```
   mvn spring-boot:run
   ```

5. The application will start running at `http://localhost:8080`

## API Endpoints

- `GET /cognito/users`: List all users in the Cognito user pool
- `GET /cognito/users/{username}`: Get details of a specific user
- `GET /cognito/identity-providers`: List all identity providers
- `POST /cognito/authenticate`: Authenticate a user and get a JWT token
  - Request body: `{ "username": "user@example.com", "password": "password123" }`
- `POST /cognito/signup`: Register a new user
  - Request body: `{ "username": "newuser@example.com", "password": "newpassword123", "email": "newuser@example.com" }`

## Configuration

Update the following properties in `src/main/resources/application.properties`:

```
aws.cognito.userPoolId=your-user-pool-id
aws.cognito.clientId=your-client-id
aws.cognito.region=your-region
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
