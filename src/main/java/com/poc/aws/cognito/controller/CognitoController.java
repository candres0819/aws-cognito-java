package com.poc.aws.cognito.controller;

import java.util.List;

import com.poc.aws.cognito.domain.AuthenticationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.poc.aws.cognito.domain.ResponseDTO;
import com.poc.aws.cognito.service.CognitoService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

@RestController
@RequestMapping("/cognito")
public class CognitoController {

    private final CognitoService cognitoService;

    public CognitoController(CognitoService cognitoService) {
        this.cognitoService = cognitoService;
    }

    /*@GetMapping("/users")
    public List<UserType> listUsers() {
        return cognitoService.listUsers();
    }

    @GetMapping("/identity-providers")
    public List<ProviderDescription> listIdentityProviders() {
        return cognitoService.listIdentityProviders();
    }*/

    @PostMapping("/auth")
    public ResponseEntity<String> authenticateUser(@RequestBody AuthenticationRequest authRequest) {
        String jwt = cognitoService.authenticateAndGetJWT(authRequest.getUsername(), authRequest.getPassword());
        return ResponseEntity.ok(jwt);
    }

    /*
    @Operation(summary = "Invalida un refresh token y todos los access token asociados a él", description = "Consumo del endpoint de Revocation de Cognito para invalidar tokens")
    @RequestBody(required = true, content = @Content(mediaType = MediaType.MULTIPART_FORM_DATA_VALUE), description = "Schema LogoutFormDto")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token revocado exitosamente", content = @Content(schema = @Schema(implementation = ResponseDTO.class), mediaType = "application/json")),
            @ApiResponse(responseCode = "400", description = "El token no pudo ser revocado o los datos recibidos no cumplen con la obligatoriedad o formatos esperados.", content = @Content(schema = @Schema(implementation = ResponseDto.class), mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error inesperado durante el proceso.", content = @Content(schema = @Schema(implementation = ResponseDTO.class), mediaType = "application/json")) })
    @PostMapping(value = "/logout", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseDTO> revokeToken(
            @Parameter(name = "Ip-Address", description = "Dirección IP desde la cual se realiza la petición", required = true, in = ParameterIn.HEADER) @RequestHeader(value = "Ip-Address") String ipAddress,
            @Parameter(name = "RefreshToken", description = "Refresh Token a invalidar", required = true, in = ParameterIn.HEADER) @RequestHeader(value = "RefreshToken") String refreshToken,
            @RequestParam(value = "token-firebase", required = false) String tokenFirebase,
            @RequestParam(value = "device-firebase", required = false) String deviceFirebase, @ModelAttribute LogoutFormDto logoutFormDto) {
        return cognitoService.revokeToken(refreshToken, logoutFormDto, tokenFirebase, deviceFirebase);
    }
    */
}
