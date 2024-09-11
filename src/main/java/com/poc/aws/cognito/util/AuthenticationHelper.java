package com.poc.aws.cognito.util;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SimpleTimeZone;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.AuthenticationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminSetUserPasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminSetUserPasswordResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminUpdateUserAttributesRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminUpdateUserAttributesResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChallengeNameType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderResponseMetadata;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.RespondToAuthChallengeRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.RespondToAuthChallengeResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException;

/**
 * Clase utilitaria que permite realizar la autenticacion contra Cognito, manejando e interpretando las respuestas retornados por este.
 * 
 */
public class AuthenticationHelper {

    /** Logger */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationHelper.class);

    /** Valor hexadeximal requerido por el proceso de autenticacion */
    private static final String HEX_N = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
            + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
            + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
            + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

    private static final String DEFAULT_ENCODING = "UTF-8";
    private static final Charset UTF8 = Charset.forName(DEFAULT_ENCODING);

    /** Valores utilizados durante el proceso de autenticacion */
    private static final String USER_ATTRIBUTE_USERNAME = "USERNAME";
    private static final BigInteger N = new BigInteger(HEX_N, 16);
    private static final BigInteger g = BigInteger.valueOf(2);
    private static final BigInteger k;
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int EPHEMERAL_KEY_LENGTH = 1024;
    private static final int DERIVED_KEY_SIZE = 16;
    private static final String DERIVED_KEY_INFO = "Caldera Derived Key";
    private static final SecureRandom SECURE_RANDOM;
    private static MessageDigest messageDigest;

    /** Variables utilitarias para el proceso de autenticacion */
    private BigInteger a;
    private BigInteger valueA;

    /** Objeto de consumo de los servicios de AWS Cognito */
    private final CognitoIdentityProviderClient cognitoIdentityProviderClient;

    private final String identityPoolId;
    private final String clientId;
    private final String userPool;

    /**
     * Define la logica basica para la interpretacion de los mensajes de respuesta del proceso de autenticacion
     */
    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");
            initMessageDigest();
            messageDigest.reset();
            messageDigest.update(N.toByteArray());
            byte[] digest = messageDigest.digest(g.toByteArray());
            k = new BigInteger(1, digest);
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e.getMessage(), e);
        }
    }

    /**
     * Metodo constructor
     */
    public AuthenticationHelper(CognitoIdentityProviderClient cognitoIdentityProviderClient, String identityPoolId, String clientId, String userPool) {
        do {
            a = new BigInteger(EPHEMERAL_KEY_LENGTH, SECURE_RANDOM).mod(N);
            valueA = g.modPow(a, N);
        } while (valueA.mod(N).equals(BigInteger.ZERO));
        this.cognitoIdentityProviderClient = cognitoIdentityProviderClient;
        this.identityPoolId = identityPoolId;
        this.clientId = clientId;
        this.userPool = userPool;
        initMessageDigest();
    }

    /**
     * Permite inicializar el objeto de decodificacion de los mensajes de respuesta del proceso de autenticacion
     */
    private static void initMessageDigest() {
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Error in AuthenticationHelper", e);
        }
    }

    /**
     * Permite obtener el valor de la variable auxiliar A
     * 
     * @return Valor de la variable
     */
    private BigInteger getValueA() {
        return valueA;
    }

    /**
     * 
     */
    private AdminUpdateUserAttributesResponse confirmEmailFromAdmin(String email) {
        AttributeType attributeTypeEmail = AttributeType
                .builder()
                .name("email_verified")
                .value("true")
                .build();

        List<AttributeType> attributeTypeList = Arrays.asList(attributeTypeEmail);

        AdminUpdateUserAttributesRequest adminUpdateUserAttributesRequest = AdminUpdateUserAttributesRequest
                .builder()
                .username(email)
                .userPoolId(userPool)
                .userAttributes(attributeTypeList)
                .build();

        
        AdminUpdateUserAttributesResponse adminUpdateUserAttributesResult =
                this.cognitoIdentityProviderClient.adminUpdateUserAttributes(adminUpdateUserAttributesRequest);
        return adminUpdateUserAttributesResult;
    }

    public CognitoIdentityProviderResponseMetadata createOrUpdateUserFromAdmin(String email, String password) throws Exception {

        /** Validar si el usuario ya existe en cognito */
        AdminGetUserRequest adminGetUserRequest = AdminGetUserRequest
                .builder()
                .username(email)
                .userPoolId(userPool)
                .build();

        AdminGetUserResponse adminGetUserResult = null;
        try {
            adminGetUserResult = this.cognitoIdentityProviderClient.adminGetUser(adminGetUserRequest);
        } catch (UserNotFoundException ex) {
            adminGetUserResult = null;
        } catch (Exception ex) {
            adminGetUserResult = null;
        }

        /** si el cliente existe en Cognito */
        if (adminGetUserResult != null) {
            if (adminGetUserResult.enabled() && adminGetUserResult.username() != null) {
                AdminSetUserPasswordResponse adminSetUserPasswordResult = setUserPasswordFromAdmin(email, password, password);

                /** Realiza la confirmacion de email al identity provider cognito */
                AdminUpdateUserAttributesResponse adminUpdateUserAttributesResult = this.confirmEmailFromAdmin(email);
                if (!adminUpdateUserAttributesResult.sdkHttpResponse().isSuccessful()) {
                    LOGGER.error("Error adminUpdateUserAttributesResult {}", adminUpdateUserAttributesResult.responseMetadata().toString());
                    throw new Exception("No se logro actualizar el usuario");
                }
                return adminSetUserPasswordResult.responseMetadata();
            }

            LOGGER.error("Usuario no activo");
            throw new Exception("Usuario no activo");
        } else {
            /** Ocurre cuando el usuario intenta iniciar sesion con codigo OTP sin haber iniciado sesion con credenciales */
            if(password == null) {
                LOGGER.error("Error createOrUpdateUserFromAdmin password nulo");
                throw new Exception("Password nulo");
            }

            AdminCreateUserRequest adminCreateUserRequest = AdminCreateUserRequest
                    .builder()
                    .username(email)
                    .userPoolId(userPool)
                    .build();

            CognitoIdentityProviderResponseMetadata cognitoIdentityProviderResponseMetadata = this.cognitoIdentityProviderClient
                    .adminCreateUser(adminCreateUserRequest)
                    .responseMetadata();
            
            AdminSetUserPasswordResponse adminSetUserPasswordResult = setUserPasswordFromAdmin(email, password, password);


            /** Realiza la confirmacion de email al identity provider cognito */
            AdminUpdateUserAttributesResponse adminUpdateUserAttributesResult = this.confirmEmailFromAdmin(email);

            return cognitoIdentityProviderResponseMetadata;
        }
    }
    
    private AdminSetUserPasswordResponse setUserPasswordFromAdmin(String userName, String password, String userPoolId) {
        AdminSetUserPasswordRequest adminSetUserPasswordRequest = AdminSetUserPasswordRequest
                .builder()
                .username(userName)
                .password(password)
                .userPoolId(userPool)
                .permanent(true)
                .build();

        AdminSetUserPasswordResponse adminSetUserPasswordResult = this.cognitoIdentityProviderClient
                .adminSetUserPassword(adminSetUserPasswordRequest);

        return adminSetUserPasswordResult;
    }


    /**
     * Orquesta la autenticacion SRP contra Cognito
     * 
     * @param username
     *            Nombre de usuario para la autenticacion
     * @param password
     *            Contraseña para la autenticacion
     * @return Token JWT en caso de que la autenticacion sea exitosa
     */
    public AuthenticationResultType performSRPAuthentication(String username, String password) {
        AuthenticationResultType authresult = null;

        InitiateAuthRequest initiateAuthRequest = this.initiateUserSrpAuthRequest(username, password);
        InitiateAuthResponse initiateAuthResponse = this.cognitoIdentityProviderClient.initiateAuth(initiateAuthRequest);

        if (ChallengeNameType.PASSWORD_VERIFIER.toString().equals(initiateAuthResponse.challengeNameAsString())) {
            RespondToAuthChallengeRequest challengeRequest = this.userSrpAuthRequest(initiateAuthResponse, password);
            RespondToAuthChallengeResponse result = this.cognitoIdentityProviderClient.respondToAuthChallenge(challengeRequest);
            authresult = result.authenticationResult();
        }

        return authresult;
    }

    /**
     * Orquesta la autenticacion SRP contra Cognito
     * 
     * @param username
     *            Nombre de usuario para la autenticacion
     * @param password
     *            Contraseña para la autenticacion
     * @return Token JWT en caso de que la autenticacion sea exitosa
     */
    public AuthenticationResultType performCustomAuthentication(String username, String password) {
        AuthenticationResultType authresult = null;

        InitiateAuthRequest initiateAuthRequest = this.initiateUserCustomAuthRequest(username, password);
        InitiateAuthResponse initiateAuthResponse = this.cognitoIdentityProviderClient.initiateAuth(initiateAuthRequest);

        if (ChallengeNameType.CUSTOM_CHALLENGE.toString().equals(initiateAuthResponse.challengeNameAsString())) {
            RespondToAuthChallengeRequest challengeRequest = this.userSrpAuthRequest(initiateAuthResponse, password);
            RespondToAuthChallengeResponse result = this.cognitoIdentityProviderClient.respondToAuthChallenge(challengeRequest);
            authresult = result.authenticationResult();
        }

        return authresult;
    }

    /**
     * Orquesta la autenticacion SRP contra Cognito
     * 
     * @param username
     *            Nombre de usuario para la autenticacion
     * @param password
     *            Contraseña para la autenticacion
     * @return Token JWT en caso de que la autenticacion sea exitosa
     */
    public AuthenticationResultType performSRPAdminAuthentication(String username, String password) {
        AuthenticationResultType authresult = null;

        AdminInitiateAuthRequest initiateAuthRequest = this.initiateUserSrpAdminAuthRequest(username, password);
        AdminInitiateAuthResponse initiateAuthResponse = cognitoIdentityProviderClient.adminInitiateAuth(initiateAuthRequest);

//        if (ChallengeNameType.PASSWORD_VERIFIER.toString().equals(initiateAuthResponse.challengeName())) {
//            RespondToAuthChallengeRequest challengeRequest = userSrpAuthRequest(initiateAuthResponse);
//            RespondToAuthChallengeResponse result = cognitoIdentityProviderClient.respondToAuthChallenge(challengeRequest);
//            authresult = result.authenticationResult();
            authresult = initiateAuthResponse.authenticationResult();
//        }
          return authresult;
    }

    /**
     * Inicia el proceso de solicitud de autenticacion
     *
     * @param username
     *            Nombre de usuario para el cual se crea la solicitud
     * @return Objeto con la informacion de la solicitud
     */
    private InitiateAuthRequest initiateUserSrpAuthRequest(String username, String password) {
        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);
        authParams.put("SRP_A", this.getValueA().toString(16));

        InitiateAuthRequest initiateAuthRequest = InitiateAuthRequest
                .builder()
                .authFlow(AuthFlowType.USER_SRP_AUTH)
                .clientId(clientId)
                .authParameters(authParams)
                .build();

        return initiateAuthRequest;
    }
    
    /**
     * Inicia el proceso de solicitud de autenticacion
     *
     * @param username
     *            Nombre de usuario para el cual se crea la solicitud
     * @return Objeto con la informacion de la solicitud
     */
    private InitiateAuthRequest initiateUserCustomAuthRequest(String username, String password) {
        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);
        authParams.put("SRP_A", this.getValueA().toString(16));

        InitiateAuthRequest initiateAuthRequest = InitiateAuthRequest
                .builder()
                .authFlow(AuthFlowType.CUSTOM_AUTH)
                .clientId(clientId)
                .authParameters(authParams)
                .build();

        return initiateAuthRequest;
    }

    /**
     * Inicia el proceso de solicitud de autenticacion
     *
     * @param username
     *            Nombre de usuario para el cual se crea la solicitud
     * @return Objeto con la informacion de la solicitud
     */
    private AdminInitiateAuthRequest initiateUserSrpAdminAuthRequest(String username, String password) {
        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);
        authParams.put("SRP_A", this.getValueA().toString(16));

        AdminInitiateAuthRequest initiateAuthRequest = AdminInitiateAuthRequest
                .builder()
//                .authFlow(AuthFlowType.CUSTOM_AUTH)
//                 .authFlow(AuthFlowType.USER_SRP_AUTH)
                 .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                // .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                .clientId(clientId)
                .userPoolId(userPool)
                .authParameters(authParams)
                .build();

        return initiateAuthRequest;
    }

    /**
     * Obtiene la respuesta del proceso de autenticacion iniciado contra el userpool
     * 
     * @param challenge
     *            Objeto con la informacion del proceso de autenticacion
     * @param password
     *            Contraseña utilizada para completar el proceso
     * @return Objeto con la respuesta del proceso de autenticacion
     */
    private RespondToAuthChallengeRequest userSrpAuthRequest(InitiateAuthResponse challenge, String password) {
        String userIdForSRP = challenge.challengeParameters().get("USER_ID_FOR_SRP");
        String usernameInternal = challenge.challengeParameters().get(USER_ATTRIBUTE_USERNAME);

        var b = new BigInteger(challenge.challengeParameters().get("SRP_B"), 16);
        if (b.mod(AuthenticationHelper.N).equals(BigInteger.ZERO)) {
            throw new SecurityException("SRP error, B cannot be zero");
        }

        var salt = new BigInteger(challenge.challengeParameters().get("SALT"), 16);
        var timestamp = new Date();
        byte[] hmac = null;
        try {
            byte[] key = getPasswordAuthenticationKey(userIdForSRP, password, b, salt);
            var mac = Mac.getInstance(HMAC_SHA256);
            var keySpec = new SecretKeySpec(key, HMAC_SHA256);
            mac.init(keySpec);
            mac.update(this.userPool.split("_", 2)[1].getBytes("UTF-8"));
            mac.update(userIdForSRP.getBytes("UTF-8"));
            byte[] secretBlock = Base64.getDecoder().decode(challenge.challengeParameters().get("SECRET_BLOCK"));
            mac.update(secretBlock);
            var simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
            simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
            var dateString = simpleDateFormat.format(timestamp);
            byte[] dateBytes = dateString.getBytes("UTF-8");
            hmac = mac.doFinal(dateBytes);
        } catch (Exception e) {
            LOGGER.error("Error in userSrpAuthRequest", e);
        }

        var formatTimestamp = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
        formatTimestamp.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));

        Map<String, String> srpAuthResponses = new HashMap<>();
        srpAuthResponses.put("PASSWORD_CLAIM_SECRET_BLOCK", challenge.challengeParameters().get("SECRET_BLOCK"));
        srpAuthResponses.put("PASSWORD_CLAIM_SIGNATURE", new String(Base64.getEncoder().encode(hmac), UTF8));
        srpAuthResponses.put("TIMESTAMP", formatTimestamp.format(timestamp));
        srpAuthResponses.put(USER_ATTRIBUTE_USERNAME, usernameInternal);
        srpAuthResponses.put("ANSWER", "true");

        RespondToAuthChallengeRequest respondToAuthChallengeRequest = RespondToAuthChallengeRequest
                .builder()
                .challengeName(challenge.challengeName())
                .clientId(clientId)
                .challengeResponses(srpAuthResponses)
                .session(challenge.session())
                .build();

        return respondToAuthChallengeRequest;
    }

    /**
     * Obtiene la clave de autenticacion correspondiente a una contraseña
     * 
     * @param userId
     *            Identificador del usuario
     * @param userPassword
     *            Contraseña del usuario
     * @param valueB
     *            Valor auxiliar para la consulta de la clave
     * @param salt
     *            Valor auxiliar para la consulta de la clave
     * @return Arreglo con el valor de la clave
     * @throws AuthenticationException
     *             En caso de error durante la autenticacion
     */
    private byte[] getPasswordAuthenticationKey(String userId, String userPassword, BigInteger valueB, BigInteger salt)
            throws AuthenticationException {
        // Authenticate the password u = H(A, B)
        messageDigest.reset();
        messageDigest.update(valueA.toByteArray());
        var u = new BigInteger(1, messageDigest.digest(valueB.toByteArray()));
        if (u.equals(BigInteger.ZERO)) {
            throw new SecurityException("Hash of A and B cannot be zero");
        }
        messageDigest.reset();
        messageDigest.update(this.userPool.split("_", 2)[1].getBytes(UTF8));
        messageDigest.update(userId.getBytes(UTF8));
        messageDigest.update(":".getBytes(UTF8));
        byte[] userIdHash = messageDigest.digest(userPassword.getBytes(UTF8));

        messageDigest.reset();
        messageDigest.update(salt.toByteArray());
        var x = new BigInteger(1, messageDigest.digest(userIdHash));
        BigInteger s = (valueB.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)).mod(N);

        Hkdf hkdf;
        try {
            hkdf = Hkdf.getInstance(HMAC_SHA256);
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e.getMessage(), e);
        }
        hkdf.init(s.toByteArray(), u.toByteArray());
        return hkdf.deriveKey(DERIVED_KEY_INFO, DERIVED_KEY_SIZE);
    }

    /**
     * Clase interna para realizar los calculos Hkdf
     */
    private static final class Hkdf {
        private static final int MAX_KEY_SIZE = 255;
        private static final byte[] EMPTY_ARRAY = new byte[0];
        private final String algorithm;
        private SecretKey prk = null;

        /**
         * Metodo constructor
         * 
         * @param algorithm
         *            REQUERIDO: Tipo de algoritmo HMAC a ser usado
         * @throws NoSuchAlgorithmException
         *             En caso de que el algoritmo recibido no cumpla con el esperado
         */
        private Hkdf(String algorithm) throws NoSuchAlgorithmException {
            if (!algorithm.startsWith("Hmac")) {
                throw new NoSuchAlgorithmException("Invalid algorithm " + algorithm + ". Hkdf may only be used with Hmac algorithms.");
            } else {
                this.algorithm = algorithm;
            }
        }

        /**
         * Permite crear una instancia de la clase utilitaria
         * 
         * @param algorithm
         *            Algoritmo a utilizar
         * @return Instancia de la clase
         * @throws NoSuchAlgorithmException
         *             En caso de error durante la instanciacion
         */
        private static Hkdf getInstance(String algorithm) throws NoSuchAlgorithmException {
            return new Hkdf(algorithm);
        }

        /**
         * Inicia el proceso para los calculos HMAC
         * 
         * @param ikm
         *            REQUERIDO: El material clave de entrada
         * @param salt
         *            REQUIRED: Bytes aleatorios para el 'SALT'
         * @throws AuthenticationException
         *             En caso de error durante le proceso
         */
        private void init(byte[] ikm, byte[] salt) throws AuthenticationException {
            byte[] realSalt = salt == null ? EMPTY_ARRAY : salt.clone();
            byte[] rawKeyMaterial = EMPTY_ARRAY;

            try {
                final var e = Mac.getInstance(this.algorithm);
                if (realSalt.length == 0) {
                    realSalt = new byte[e.getMacLength()];
                    Arrays.fill(realSalt, (byte) 0);
                }

                e.init(new SecretKeySpec(realSalt, this.algorithm));
                rawKeyMaterial = e.doFinal(ikm);
                final var key = new SecretKeySpec(rawKeyMaterial, this.algorithm);
                Arrays.fill(rawKeyMaterial, (byte) 0);
                this.unsafeInitWithoutKeyExtraction(key);
            } catch (final GeneralSecurityException var10) {
                throw new AuthenticationException("Unexpected exception", var10);
            } finally {
                Arrays.fill(rawKeyMaterial, (byte) 0);
            }

        }

        /**
         * Inicializa de manera insegura el proceso de calculo HMAC
         * 
         * @param rawKey
         *            REQUIRED: Clave secret actual
         * @throws InvalidKeyException
         *             En caso de que se reciba una clave invalida
         */
        private void unsafeInitWithoutKeyExtraction(SecretKey rawKey) throws InvalidKeyException {
            if (!rawKey.getAlgorithm().equals(this.algorithm)) {
                throw new InvalidKeyException("Algorithm for the provided key must match the algorithm for this Hkdf. Expected "
                        + this.algorithm + " but found " + rawKey.getAlgorithm());
            } else {
                this.prk = rawKey;
            }
        }

        /**
         * Deriva una clave HMAC
         * 
         * @param info
         *            REQUERIDO
         * @param length
         *            REQUIRED
         * @return Bytes de la clave derivada
         * @throws AuthenticationException
         *             En caso de error durante el proceso
         */
        private byte[] deriveKey(String info, int length) throws AuthenticationException {
            return this.deriveKey(info != null ? info.getBytes(UTF8) : null, length);
        }

        /**
         * Deriva una clave HMAC
         * 
         * @param info
         *            REQUERIDO
         * @param length
         *            REQUERIDO
         * @return Bytes convertidos
         * @throws AuthenticationException
         *             En caso de error durante el proceso
         */
        private byte[] deriveKey(byte[] info, int length) throws AuthenticationException {
            final var result = new byte[length];

            try {
                this.deriveKey(info, length, result, 0);
                return result;
            } catch (final ShortBufferException var5) {
                throw new AuthenticationException(var5.getMessage(), var5);
            }
        }

        /**
         * Deriva una clave HMAC
         * 
         * @param info
         *            REQUERIDO
         * @param length
         *            REQUERIDO
         * @param output
         *            REQUERIDO
         * @param offset
         *            REQUERIDO
         * @throws ShortBufferException
         *             En caso de superar el tamaño del buffer
         * @throws AuthenticationException
         *             En caso de error durante el proceso
         */
        private void deriveKey(byte[] info, int length, byte[] output, int offset) throws ShortBufferException, AuthenticationException {
            this.assertInitialized();
            if (length < 0) {
                throw new IllegalArgumentException("Length must be a non-negative value.");
            } else if (output.length < offset + length) {
                throw new ShortBufferException();
            } else {
                final var mac = this.createMac();
                if (length > MAX_KEY_SIZE * mac.getMacLength()) {
                    throw new IllegalArgumentException("Requested keys may not be longer than 255 times the underlying HMAC length.");
                } else {
                    byte[] t = EMPTY_ARRAY;

                    try {
                        var loc = 0;

                        for (byte i = 1; loc < length; ++i) {
                            mac.update(t);
                            mac.update(info);
                            mac.update(i);
                            t = mac.doFinal();

                            for (var x = 0; x < t.length && loc < length; ++loc, ++x) {
                                output[loc] = t[x];
                            }
                        }
                    } finally {
                        Arrays.fill(t, (byte) 0);
                    }

                }
            }
        }

        /**
         * Crea una Mac
         * 
         * @return el código de autenticación del mensaje generado.
         * @throws AuthenticationException
         *             En caso de error durante el proceso
         */
        private Mac createMac() throws AuthenticationException {
            try {
                final var ex = Mac.getInstance(this.algorithm);
                ex.init(this.prk);
                return ex;
            } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
                throw new AuthenticationException(e.getMessage(), e);
            }
        }

        /**
         * Comprueba una clave pseudoaleatoria válida.
         */
        private void assertInitialized() {
            if (this.prk == null) {
                throw new IllegalStateException("Hkdf has not been initialized");
            }
        }
    }

    public static Integer getVersionValue(String version) {
        String[] parts = version.split("\\.");
        List<String> partsList = Arrays.asList(parts);
        StringBuilder preVersion = new StringBuilder();
        for (String part : partsList) {
            Integer partFormated = Integer.valueOf(part) + 100;
            preVersion.append(partFormated.toString().substring(1, 3));
        }
        return Integer.valueOf(String.valueOf(preVersion));
    }
}