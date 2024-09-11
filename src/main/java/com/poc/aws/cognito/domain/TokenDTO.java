package com.poc.aws.cognito.domain;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@Schema(name = "TokenDTO")
public class TokenDTO {

    /** Token de acceso a los recursos */
    private String accessToken;
    /** Token de identificacion y autorizacion */
    private String idToken;
    /** Token de actualizacion de la identidad */
    private String refreshToken;
    /** Tiempo en segundas para la expiracion del token */
    private Integer expiresIn;

    // create constructor
    public TokenDTO(String accessToken, String idToken, String refreshToken, Integer expiresIn) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
    }
}