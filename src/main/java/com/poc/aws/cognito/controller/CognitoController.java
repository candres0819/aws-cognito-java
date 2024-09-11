package com.poc.aws.cognito.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.poc.aws.cognito.domain.AuthenticationRequest;
import com.poc.aws.cognito.domain.TokenDTO;
import com.poc.aws.cognito.service.CognitoService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;

@RestController
@RequestMapping("/cognito")
public class CognitoController {

    private final CognitoService cognitoService;

    public CognitoController(CognitoService cognitoService) {
        this.cognitoService = cognitoService;
    }

    /*
     * @GetMapping("/users") public List<UserType> listUsers() { return cognitoService.listUsers(); }
     * 
     * @GetMapping("/identity-providers") public List<ProviderDescription> listIdentityProviders() { return
     * cognitoService.listIdentityProviders(); }
     */

    @Operation(summary = "Permite al usuario autenticarse temporalmente", description = "Login en amazon Cognito")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Objeto JSON con las credenciales", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = AuthenticationRequest.class)))
    @PostMapping(value = "/auth-custom", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> authenticateUserCustom(@RequestBody AuthenticationRequest authRequest) {
        String jwt = cognitoService.authenticateAndGetJWT(authRequest.getUsername(), authRequest.getPassword());
        return ResponseEntity.ok(jwt);
    }

    @Operation(summary = "Permite al usuario autenticarse temporalmente", description = "Login en amazon Cognito")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Objeto JSON con las credenciales", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = AuthenticationRequest.class)))
    @PostMapping(value = "/auth-srp", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenDTO> authenticateUserSRP(@RequestBody AuthenticationRequest authRequest) {
        TokenDTO jwt = cognitoService.authenticateUserTMPAndGetJWT(authRequest.getUsername(), authRequest.getPassword());
        return ResponseEntity.ok(jwt);
    }

    /*
     * @Operation(summary = "Invalida un refresh token y todos los access token asociados a él", description =
     * "Consumo del endpoint de Revocation de Cognito para invalidar tokens")
     * 
     * @RequestBody(required = true, content = @Content(mediaType = MediaType.MULTIPART_FORM_DATA_VALUE), description =
     * "Schema LogoutFormDto")
     * 
     * @ApiResponses(value = {
     * 
     * @ApiResponse(responseCode = "200", description = "Token revocado exitosamente", content = @Content(schema = @Schema(implementation =
     * ResponseDTO.class), mediaType = "application/json")),
     * 
     * @ApiResponse(responseCode = "400", description =
     * "El token no pudo ser revocado o los datos recibidos no cumplen con la obligatoriedad o formatos esperados.", content
     * = @Content(schema = @Schema(implementation = ResponseDto.class), mediaType = "application/json")),
     * 
     * @ApiResponse(responseCode = "500", description = "Error inesperado durante el proceso.", content = @Content(schema
     * = @Schema(implementation = ResponseDTO.class), mediaType = "application/json")) })
     * 
     * @PostMapping(value = "/logout", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE) public
     * ResponseEntity<ResponseDTO> revokeToken(
     * 
     * @Parameter(name = "Ip-Address", description = "Dirección IP desde la cual se realiza la petición", required = true, in =
     * ParameterIn.HEADER) @RequestHeader(value = "Ip-Address") String ipAddress,
     * 
     * @Parameter(name = "RefreshToken", description = "Refresh Token a invalidar", required = true, in =
     * ParameterIn.HEADER) @RequestHeader(value = "RefreshToken") String refreshToken,
     * 
     * @RequestParam(value = "token-firebase", required = false) String tokenFirebase,
     * 
     * @RequestParam(value = "device-firebase", required = false) String deviceFirebase, @ModelAttribute LogoutFormDto logoutFormDto) {
     * return cognitoService.revokeToken(refreshToken, logoutFormDto, tokenFirebase, deviceFirebase); }
     */
}
