package com.nicolas.app_academy.services.implementations;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nicolas.app_academy.components.HttpComponent;
import com.nicolas.app_academy.dto.Login;
import com.nicolas.app_academy.dto.Register;
import com.nicolas.app_academy.services.ILoginService;
import com.nicolas.app_academy.utils.HttpParamsMapBuilder;

@Service
public class LoginServiceKeycloakImpl implements ILoginService<String> {

  @Value("${keycloak.auth-server-url}")
  private String keyCloakServerUrl;

  @Value("${keycloak.realm}")
  private String realm;

  @Value("${keycloak.resource}")
  private String clientId;

  @Value("${keycloak.credentials.secret}")
  private String clientSecret;

  @Value("${keycloak.user-login.grant-type}")
  private String grantType;

  @Value("${base.url}")
  private String baseUrl;

  @Autowired
  private HttpComponent httpComponent;

  @Override
  public ResponseEntity<String> login(Login login) {
    httpComponent.httpHeaders().setContentType(MediaType.APPLICATION_FORM_URLENCODED);

    MultiValueMap<String, String> map = HttpParamsMapBuilder.builder()
        .withClient(clientId)
        .withClientSecret(clientSecret)
        .withGrantType(grantType)
        .withUsername(login.email())
        .withPassword(login.password())
        .build();

    HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, httpComponent.httpHeaders());

    try {
      ResponseEntity<String> response = httpComponent.restTemplate().postForEntity(
          keyCloakServerUrl + "/protocol/openid-connect/token", request, String.class);

      String responseBody = response.getBody();
      ObjectMapper mapper = new ObjectMapper();
      JsonNode root = mapper.readTree(responseBody);

      String accessToken = root.path("access_token").asText();

      DecodedJWT decodedJWT = JWT.decode(accessToken);
      Claim claim = decodedJWT.getClaim("realm_access");
      Map<String, Object> realmAccessMap = claim.asMap();

      List<String> roles = new ArrayList<>();
      if (realmAccessMap != null && realmAccessMap.containsKey("roles")) {
        Object rolesObj = realmAccessMap.get("roles");
        if (rolesObj instanceof List<?>) {
          for (Object role : (List<?>) rolesObj) {
            roles.add(String.valueOf(role));
          }
        }
      }

      if (roles.contains("Unifit")) {
        return ResponseEntity.ok(responseBody);
      } else {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
      }
    } catch (HttpClientErrorException e) {
      return ResponseEntity.status(e.getStatusCode()).body(e.getMessage());
    } catch (JsonProcessingException e) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erro ao processar JSON: " + e.getMessage());
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erro inesperado: " + e.getMessage());
    }
  }

  @Override
  public ResponseEntity<String> register(Register register) {
    String accessToken = getKeycloakAccessToken();
    String createUserUrl = baseUrl + "/admin/realms/" + realm + "/users";

    Map<String, Object> user = new HashMap<>();
    user.put("username", register.username());
    user.put("email", register.email());
    user.put("enabled", true);
    user.put("emailVerified", true);

    Map<String, Object> credentials = new HashMap<>();
    credentials.put("type", "password");
    credentials.put("value", register.password());
    credentials.put("temporary", false);

    user.put("credentials", Arrays.asList(credentials));

    HttpHeaders headers = new HttpHeaders();
    headers.set("Authorization", "Bearer " + accessToken);
    headers.setContentType(MediaType.APPLICATION_JSON);

    HttpEntity<Map<String, Object>> request = new HttpEntity<>(user, headers);

    try {
      ResponseEntity<String> response = httpComponent.restTemplate().postForEntity(createUserUrl, request, String.class);

      //A Admin API do Keycloak responde 201 Ceated com o corpo vazio ao criar um usuario. O ID do usuario recem-criado vem no
      //header "Location", nao no corpo da resposta. Extrai esse ID aqui para poder atribuir a role "Unifit" a ele em seguida
      String location = response.getHeaders().getLocation() != null
              ? response.getHeaders().getLocation().toString() : null;

      //Se nao veio o header Location, nao tem como saber o ID do usuario criado
      if(location == null){
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Usuário criado, mas não foi possível obter o ID para atribuir a role!");
      }

      //O header Location tem o formato: .../users/{userId}, pego o ultimo trecho
      String[] locationParts = location.split("/");
      String newUserId = locationParts[locationParts.length - 1];

      //Usuarios criados via cadastro precisam da role "Unifit" para conseguir logar depois. Antes, essa role so era atribuida
      //manualmente pelo admin no painel do Keycloak. Agora, é atribuida automaticamente nessa parte
      assignUnifitRole(newUserId, accessToken);

      //Como o corpo da criacao vem vazio, devolvo uma mensagem propria para o frontend, em vez de "response.getBody()" que
      //ficaria nulo e vazia o frontend tratar como falha silenciosa, sem toast nem redirecionamento
      Map<String, String> body = new HashMap<>();
      body.put("message", "Usuário criado com sucesso!");
      return ResponseEntity.ok(new ObjectMapper().writeValueAsString(body));

      //Correcao temporaria: e.getMessage so mostra o status generico (403), sem o corpo da resposta do Keycloak,
      //que geralmente contem o motivo real do erro
    } catch (HttpClientErrorException e) {
      return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
    } catch (JsonProcessingException e){
      //Necessario capturar pois mapper.writeValueAsString() acima pode lancar esse erro
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erro ao montar resposta de sucesso: " + e.getMessage());
    }
  }

  //Novo metodo: Busca o ID interno da role "Unifit" no realm e atribui ao usuario recem-criado.
  //Pois o Keycloak exige o ID interno da role (nao so o nome) para fazer a atribuicao via admin API
  private void assignUnifitRole(String userId, String accessToken){
    HttpHeaders headers = new HttpHeaders();
    headers.set("Authorization", "Bearer " + accessToken);
    headers.setContentType(MediaType.APPLICATION_JSON);

    //Busca os dados da role "Unifit" (incluindo o ID interno dela)
    String getRoleUrl = baseUrl + "/admin/realms/" + realm + "/roles/Unifit";
    HttpEntity<Void> getRoleRequest = new HttpEntity<>(headers);
    ResponseEntity<String> roleResponse = httpComponent.restTemplate().exchange(getRoleUrl, HttpMethod.GET, getRoleRequest, String.class);

    Map<String, Object> roleData;
    try {
      ObjectMapper mapper = new ObjectMapper();
      roleData = mapper.readValue(roleResponse.getBody(), Map.class);
    } catch (JsonProcessingException e){
      throw new RuntimeException("Erro ao processar dados da role Unifit: " + e.getMessage());
    }

    //Monta o corpo esperado pelo Keycloak para atribuir a role: uma lista contendo um objeto com o id e name da role
    Map<String, Object> roleToAssign = new HashMap<>();
    roleToAssign.put("id", roleData.get("id"));
    roleToAssign.put("name", roleData.get("name"));

    String assignRoleUrl = baseUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm";
    HttpEntity<List<Map<String, Object>>> assignRequest = new HttpEntity<>(Arrays.asList(roleToAssign), headers);

    //Atribui a role ao usuario
    httpComponent.restTemplate().postForEntity(assignRoleUrl, assignRequest, String.class);
  }

  private String getKeycloakAccessToken() {
    String url = keyCloakServerUrl + "/protocol/openid-connect/token";
    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
    map.add("client_id", clientId);
    map.add("client_secret", clientSecret);
    map.add("grant_type", "client_credentials");

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

    HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

    try {
      ResponseEntity<Map> response = httpComponent.restTemplate().exchange(url, HttpMethod.POST, request, Map.class);
      return (String) response.getBody().get("access_token");
    } catch (HttpClientErrorException e) {
      throw new RuntimeException("Failed to authenticate with Keycloak", e);
    }
  }
}
