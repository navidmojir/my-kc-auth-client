package ir.mojir.my_kc_auth_client.external;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import ir.mojir.my_kc_auth_client.config.KeycloakConfiguration;
import ir.mojir.my_kc_auth_client.dtos.KcAccessTokenResp;
import ir.mojir.my_kc_auth_client.dtos.KcAssignRoleToUserReqRow;
import ir.mojir.my_kc_auth_client.dtos.KcAuthorizeResp;
import ir.mojir.my_kc_auth_client.dtos.KcCreateAuthorizationPolicyReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreateClientReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreateClientRoleReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreatePermissionReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreateRealmReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreateResourceReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreateResourceResp;
import ir.mojir.my_kc_auth_client.dtos.KcCreateUserReq;
import ir.mojir.my_kc_auth_client.dtos.KcFetchClientSecretResp;
import ir.mojir.my_kc_auth_client.dtos.KcGetAllClientAuthorizationPoliciesRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcGetAvailableClientRolesForUserRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcGetAvailableRealmRolesForUserRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcGetClientResp;
import ir.mojir.my_kc_auth_client.dtos.KcGetClientRoleDetailsResp;
import ir.mojir.my_kc_auth_client.dtos.KcGetPermissionResp;
import ir.mojir.my_kc_auth_client.dtos.KcGetPolicyResp;
import ir.mojir.my_kc_auth_client.dtos.KcGetServiceAccountUserIdResp;
import ir.mojir.my_kc_auth_client.dtos.KcGetUsersInClientRoleRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcResetPasswordReq;
import ir.mojir.my_kc_auth_client.dtos.KcScope;
import ir.mojir.my_kc_auth_client.dtos.KcSearchClientRoleRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcSearchUserRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcUserDetails;
import ir.mojir.my_kc_auth_client.exceptions.KeycloakAuthorizationClientException;
import ir.mojir.my_kc_auth_client.logic.ClientResourcesCache;
import ir.mojir.spring_boot_commons.exceptions.InternalErrorException;
import ir.mojir.spring_boot_commons.exceptions.UnauthorizedException;

@Component
public class KeycloakClient {

//	private final static Logger logger = LoggerFactory.getLogger(KeycloakClient.class);

	@Autowired
	private KeycloakConfiguration params;

	private String clientAccessToken = null;


	public KcCreateResourceResp createResource(String path, String method) {

		getAccessTokenForClient();

		RestTemplate restTemplate = new RestTemplate();

		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(clientAccessToken);

		KcCreateResourceReq req = new KcCreateResourceReq();
		KcScope scope = new KcScope();
		scope.setName(method);
		req.setResource_scopes(Collections.singletonList(scope));
		req.setScopes(Collections.singletonList(scope));
		req.setName(method + " - " + path);
		req.setDisplayName(method + " - " + path);
		req.setUris(Collections.singletonList(path));

		HttpEntity<KcCreateResourceReq> requestEntity = new HttpEntity<KcCreateResourceReq>(req, headers);

		return restTemplate.postForObject(params.getAuthServerUrl() + "/realms/" +
				params.getKcRealm()	+ "/authz/protection/resource_set", requestEntity, KcCreateResourceResp.class);
	}

	public String[] searchResources(String path, String method) {
		getAccessTokenForClient();
		RestTemplate restTemplate = new RestTemplate();

		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(clientAccessToken);

		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("path", path);
		uriVariables.put("method", method);

		HttpEntity<String> entity = new HttpEntity<>(headers);



		return restTemplate.exchange(params.getAuthServerUrl() + "/realms/" +
				params.getKcRealm()	+"/authz/protection/resource_set?uri={path}&scope={method}",
				HttpMethod.GET,
				entity,
				String[].class,
				uriVariables).getBody();
	}

	public String getAccessTokenForClient() {
		//here I should check expiration time of token and renew only if needed
//		if(clientAccessToken != null)
//			return;

		RestTemplate restTemplate = new RestTemplate();

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
		formData.add("grant_type", "client_credentials");
		formData.add("client_id", params.getClientId());
		formData.add("client_secret", params.getClientSecret());

		HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);


		KcAccessTokenResp resp = restTemplate.postForObject(params.getAuthServerUrl() + "/realms/" +
				params.getKcRealm()	+ "/protocol/openid-connect/token", requestEntity, KcAccessTokenResp.class);

		clientAccessToken = resp.getAccess_token();
		return clientAccessToken;
	}

	public String getAdminAccessToken(String adminUserName, String adminPassword) {
		RestTemplate restTemplate = new RestTemplate();

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
		formData.add("grant_type", "password");
		formData.add("client_id", "admin-cli");
		formData.add("username", adminUserName);
		formData.add("password", adminPassword);

		HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);


		KcAccessTokenResp resp = restTemplate.postForObject(params.getAuthServerUrl() + "/realms/master"
				+ "/protocol/openid-connect/token", requestEntity, KcAccessTokenResp.class);

		return resp.getAccess_token();
	}

	public boolean authorize(String accessToken, String path, String method) {
		try {

			RestTemplate restTemplate = new RestTemplate();

			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			headers.setBearerAuth(accessToken);

			MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
			formData.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
			formData.add("audience", params.getClientId());
			formData.add("response_mode", "decision");
			formData.add("permission", getPermissionId(path, method) + "#" + method);

			HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);


			KcAuthorizeResp resp = restTemplate.postForObject(params.getAuthServerUrl() + "/realms/" +
					params.getKcRealm() + "/protocol/openid-connect/token", requestEntity, KcAuthorizeResp.class);

			return resp.isResult();
		} catch (HttpClientErrorException e) {
			if(e.getMessage().contains("not_authorized"))
				return false;
			else if(e.getStatusCode() == HttpStatus.UNAUTHORIZED)
				throw new UnauthorizedException("Access token is invalid");
			throw new KeycloakAuthorizationClientException("Http client returned unexpected error while authorizing", e);
		} catch (Exception e) {
			throw new KeycloakAuthorizationClientException("Unexpected error occured while authorizing", e);
		}


	}

	private String getPermissionId(String path, String method) {
		return ClientResourcesCache.getInstance().get(path, method);
	}

	public KcUserDetails getUserDetails(String userId) {
		getAccessTokenForClient();

		RestTemplate restTemplate = new RestTemplate();

		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(clientAccessToken);

		HttpEntity<String> entity = new HttpEntity<>(headers);

		KcUserDetails result = restTemplate.exchange(params.getAuthServerUrl() + "/admin/realms/" + params.getKcRealm()
						+ "/users/"+userId,
				HttpMethod.GET,
				entity,
				KcUserDetails.class
				).getBody();

		result.setRetrievalTime(new Date());
		return result;
	}


	/*public KcSearchClientRespRow[] searchClientsByClientId(String clientId) {
		getAccessTokenForClient();

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(clientAccessToken);
		HttpEntity<String> entity = new HttpEntity<>(headers);
		return restTemplate.exchange(params.getAuthServerUrl() + "/admin/realms/" + params.getKcRealm()
						+ "/clients?clientId="+ clientId,
				HttpMethod.GET,
				entity,
				KcSearchClientRespRow[].class
		).getBody();
	}*/

	public void createClientRole(KcCreateClientRoleReq req) {
		createClientRole(params.getClientUuid(), req);
	}

	public void createClientRole(String clientUuid, KcCreateClientRoleReq req) {
		getAccessTokenForClient();
		createClientRole(clientUuid, req, clientAccessToken);
	}

	public void createClientRole(String clientUuid, KcCreateClientRoleReq req, String accessToken) {
		String url = String.format("/admin/realms/%s/clients/%s/roles",
				params.getKcRealm(), clientUuid);
		callPost(url, req, new ParameterizedTypeReference<Void>() {}, accessToken);
	}

	private <REQ, RESP> RESP callPost(String url, REQ req, ParameterizedTypeReference<RESP> responseType) {
		getAccessTokenForClient();
		return callPost(url, req, responseType, clientAccessToken);
	}

	private <REQ, RESP> RESP callPost(String url, REQ req, ParameterizedTypeReference<RESP> responseType, String accessToken) {
		return callPostAsResponseEntity(url, req, responseType, accessToken).getBody();
	}
	private <REQ, RESP> ResponseEntity<RESP> callPostAsResponseEntity(String url, REQ req, ParameterizedTypeReference<RESP> responseType, String accessToken) {
//		Class<RESP> respClass;

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(accessToken);
		HttpEntity<REQ> entity = new HttpEntity<>(req, headers);
		return restTemplate.exchange(
				params.getAuthServerUrl() + url,
				HttpMethod.POST,
				entity,
				responseType
		);
	}

	private <REQ, RESP> ResponseEntity<RESP> callPutAsResponseEntity(String url, REQ req, ParameterizedTypeReference<RESP> responseType, String accessToken) {
//		Class<RESP> respClass;

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(accessToken);
		HttpEntity<REQ> entity = new HttpEntity<>(req, headers);
		return restTemplate.exchange(
				params.getAuthServerUrl() + url,
				HttpMethod.PUT,
				entity,
				responseType
		);
	}

	private <RESP> RESP callGet(String url, ParameterizedTypeReference<RESP> responseType) {
		getAccessTokenForClient();
		return callGet(url, responseType, clientAccessToken);
	}
	private <RESP> RESP callGet(String url, ParameterizedTypeReference<RESP> responseType, String accessToken) {
		return callGetAsResponseEntity(url, responseType, accessToken).getBody();
	}

	private <RESP> ResponseEntity<RESP> callGetAsResponseEntity(String url, ParameterizedTypeReference<RESP> responseType, String accessToken) {
//		Class<RESP> respClass;

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(accessToken);
		HttpEntity<String> entity = new HttpEntity<>(headers);
		return restTemplate.exchange(
				params.getAuthServerUrl() + url,
				HttpMethod.GET,
				entity,
				responseType
		);
	}

	private <RESP> ResponseEntity<RESP> callDeleteAsResponseEntity(String url, ParameterizedTypeReference<RESP> responseType, String accessToken) {
//		Class<RESP> respClass;

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(accessToken);
		HttpEntity<String> entity = new HttpEntity<>(headers);
		return restTemplate.exchange(
				params.getAuthServerUrl() + url,
				HttpMethod.DELETE,
				entity,
				responseType
		);
	}



	public KcSearchClientRoleRespRow[] getAllClientRoles() {
		return getAllClientRoles(params.getClientUuid());
	}

	public KcSearchClientRoleRespRow[] getAllClientRoles(String clientUuid) {
		getAccessTokenForClient();
		return getAllClientRoles(clientUuid, clientAccessToken);
	}

	public KcSearchClientRoleRespRow[] getAllClientRoles(String clientUuid, String accessToken) {
		String url = String.format("/admin/realms/%s/clients/%s/roles", params.getKcRealm(), clientUuid);
		return callGet(url, new ParameterizedTypeReference<KcSearchClientRoleRespRow[]>() {}, accessToken);
	}

	public KcGetUsersInClientRoleRespRow[] getUsersInClientRole(String roleName) {
		String url = String.format("/admin/realms/%s/clients/%s/roles/%s/users",
				params.getKcRealm(), params.getClientUuid(), roleName);
		return callGet(url, new ParameterizedTypeReference<KcGetUsersInClientRoleRespRow[]>() {});
	}

	public void createAuthorizationPolicy(KcCreateAuthorizationPolicyReq req) {
		String url = String.format("/admin/realms/%s/clients/%s/authz/resource-server/policy/role",
			 	params.getKcRealm(), params.getClientUuid());
		callPost(url, req, new ParameterizedTypeReference<Void>() {});
	}

	public KcGetClientRoleDetailsResp getClientRoleDetails(String roleName) {
		String url = String.format("/admin/realms/%s/clients/%s/roles/%s",
				params.getKcRealm(), params.getClientUuid(), roleName);
		return callGet(url, new ParameterizedTypeReference<KcGetClientRoleDetailsResp>() {});
	}

	public KcGetAllClientAuthorizationPoliciesRespRow[] getAllClientAuthorizationPolicies() {
		String url = String.format("/admin/realms/%s/clients/%s/authz/resource-server/policy",
				params.getKcRealm(), params.getClientUuid());
		return callGet(url, new ParameterizedTypeReference<KcGetAllClientAuthorizationPoliciesRespRow[]>() {});
	}

	public void createPermission(KcCreatePermissionReq req) {
		String url = String.format("/admin/realms/%s/clients/%s/authz/resource-server/permission/scope",
				params.getKcRealm(), params.getClientUuid());
		callPost(url, req, new ParameterizedTypeReference<Void>() {});
	}

	public void createRealm(KcCreateRealmReq req, String adminAccessToken) {
		callPost("/admin/realms", req, new ParameterizedTypeReference<Void>() {}, adminAccessToken);
	}

	public boolean isRealmExists(String realmName, String adminAccessToken) {
		try {
			ResponseEntity<Void> resp = callGetAsResponseEntity("/admin/realms/" + realmName,
					new ParameterizedTypeReference<Void>() {
					}, adminAccessToken);
			return resp.getStatusCode().is2xxSuccessful();
		} catch(HttpClientErrorException.NotFound e) {
			return false;
		}
	}

	public boolean isClientExists(String clientId, String adminAccessToken) {
		KcGetClientResp resp = getClient(clientId, adminAccessToken);
		if(resp == null)
			return false;
		return true;
	}

	public KcGetClientResp getClient(String clientId, String adminAccessToken) {
		try {
			String url = "/admin/realms/" + params.getKcRealm() + "/clients?clientId=" + clientId;
			List<KcGetClientResp> resp = callGet(url,
					new ParameterizedTypeReference<List<KcGetClientResp>>() {},
					adminAccessToken);
			if(resp != null && !resp.isEmpty())
				return resp.get(0);
			else
				return null;
		} catch(HttpClientErrorException.NotFound e) {
			return null;
		}
	}

	public void createClient(KcCreateClientReq req, String adminAccessToken) {
		String url = "/admin/realms/" + params.getKcRealm() + "/clients";
		callPost(url, req, new ParameterizedTypeReference<Void>() {}, adminAccessToken);

	}

	public String fetchClientSecret(String clientUuid, String adminAccessToken) {
		String url = String.format("/admin/realms/%s/clients/%s/client-secret", params.getKcRealm(), clientUuid);
		KcFetchClientSecretResp resp = callGet(url, new ParameterizedTypeReference<KcFetchClientSecretResp>() {}, adminAccessToken);
		return resp.getValue();
	}

	public KcGetServiceAccountUserIdResp getServiceAccountUserId(String clientUuid, String adminAccessToken) {
		String url = String.format("/admin/realms/%s/clients/%s/service-account-user", params.getKcRealm(), clientUuid);
		return callGet(url, new ParameterizedTypeReference<KcGetServiceAccountUserIdResp>() {}, adminAccessToken);
	}

	public void assignClientRoleToUser(String userId, String clientUuid, KcAssignRoleToUserReqRow[] req, String adminAccessToken) {
		String url = String.format("/admin/realms/%s/users/%s/role-mappings/clients/%s", params.getKcRealm(), userId, clientUuid);
		callPost(url, req, new ParameterizedTypeReference<Void>() {}, adminAccessToken);
	}

	public void assignRealmRoleToUser(String realm, String userId, KcAssignRoleToUserReqRow[] req, String adminAccessToken) {
		String url = String.format("/admin/realms/%s/users/%s/role-mappings/realm", realm, userId);
		callPost(url, req, new ParameterizedTypeReference<Void>() {}, adminAccessToken);
	}

	public KcGetAvailableClientRolesForUserRespRow[] getAvailableClientRolesForUser(String userId, String adminAccessToken, String search) {
		String url = String.format("/admin/realms/%s/ui-ext/available-roles/users/%s?search=%s", params.getKcRealm(), userId, search);
		return callGet(url, new ParameterizedTypeReference<KcGetAvailableClientRolesForUserRespRow[]>() {}, adminAccessToken);
	}

	public KcGetAvailableRealmRolesForUserRespRow[] getAvailableRealmRolesForUser(String realm, String userId, String adminAccessToken, String search) {
		String url = String.format("/admin/realms/%s/users/%s/role-mappings/realm/available?search=%s", realm, userId, search);
		return callGet(url, new ParameterizedTypeReference<KcGetAvailableRealmRolesForUserRespRow[]>() {}, adminAccessToken);
	}

	public KcGetPolicyResp getPolicyByName(String clientUuid, String policyName) {
		getAccessTokenForClient();
		String url = String.format("/admin/realms/%s/clients/%s/authz/resource-server/policy?name=%s",
				params.getKcRealm(), clientUuid, policyName);
		KcGetPolicyResp[] result = callGet(url, new ParameterizedTypeReference<KcGetPolicyResp[]>() {}, clientAccessToken);

		if(result == null || result.length == 0)
			return null;
		if(result.length > 1) {
			for(KcGetPolicyResp r: result) {
				if(r.getName().equals(policyName))
					return r;
			}
			throw new InternalErrorException("While searching for policy with name " + policyName + " in keycloak, the result was unrelated!", null);
		}
		return result[0];
	}

	//This method became dirty because I had some challenges with paths like /tickets/{id}
	//The error was: Not enough variable values available to expand 'id'
	public KcGetPermissionResp getPermissionByName(String clientUuid, String permissionName) {
//		String encodedPermissionName = permissionName.replace("{", "%7B").replace("}", "%7D");
		getAccessTokenForClient();
		String encodedPermissionName = null;
		try {
			encodedPermissionName = URLEncoder.encode(permissionName, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException("Failed to encode permission name with value " + permissionName, e);
		}
		String url = String.format("/admin/realms/%s/clients/%s/authz/resource-server/permission?name=%s",
				params.getKcRealm(), clientUuid, encodedPermissionName);


		URI uri = null;
		try {
			uri = new URI(params.getAuthServerUrl() + url);
		} catch (URISyntaxException e) {
			throw new InternalErrorException("Failed to convert url " + params.getAuthServerUrl() + url + " to uri", e);
		}

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(clientAccessToken);
		HttpEntity<String> entity = new HttpEntity<>(headers);
		KcGetPermissionResp[] result = restTemplate.exchange(
				uri,
				HttpMethod.GET,
				entity,
				KcGetPermissionResp[].class
		).getBody();

		if(result == null || result.length == 0)
			return null;
		else if(result.length == 1)
		{
			if(result[0].getName().equals(permissionName))
				return result[0];
			return null;
		}
		else if(result.length > 1) {
			for (KcGetPermissionResp p : result) {
				if (p.getName().equals(permissionName))
					return p;
			}
			return null;
		} else {
			throw new InternalErrorException("Unexpected situation in getting permission. result length is negative!", null);
		}
	}

	public String createUser(String realm, KcCreateUserReq req, String adminAccessToken) {
		String url = String.format("/admin/realms/%s/users", realm);
		ResponseEntity<Void> resp = callPostAsResponseEntity(url, req, new ParameterizedTypeReference<Void>() {},
				adminAccessToken);

		URI location = resp.getHeaders().getLocation();
		String[] locationPathParts = location.getPath().split("/");
		return locationPathParts[locationPathParts.length - 1];
	}

	public void resetAdminPassword(String realm, String userId, KcResetPasswordReq req, String adminAccessToken) {
		String url = String.format("/admin/realms/%s/users/%s/reset-password", realm, userId);
		callPutAsResponseEntity(url, req, new ParameterizedTypeReference<Void>() {}, adminAccessToken);
	}

	public void deleteUser(String realm, String userId, String adminAccessToken) {
		String url = String.format("/admin/realms/%s/users/%s", realm, userId);
		callDeleteAsResponseEntity(url, new ParameterizedTypeReference<Void>() {}, adminAccessToken);
	}

	public KcSearchUserRespRow[] searchUsers(String username, String realm, String adminAccessToken) {
		String url = String.format("/admin/realms/%s/ui-ext/brute-force-user?briefRepresentation=true&search=%s", realm, username);
		return callGet(url, new ParameterizedTypeReference<KcSearchUserRespRow[]>() {}, adminAccessToken);
	}

	public boolean isUserExists(String username, String realm, String adminAccessToken) {
		KcSearchUserRespRow[] result = searchUsers(username ,realm, adminAccessToken);
		if(result == null || result.length == 0)
			return false;
		for(KcSearchUserRespRow row: result) {
			if(row.getUsername().equals(username))
				return true;
		}
		return false;
	}
	
	public KcAccessTokenResp getAccessTokenWithClientCredentials(String authServerUrl, String realm, String clientId, String clientSecret) {
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("grant_type", "client_credentials");
		map.add("client_id", clientId);
		map.add("client_secret", clientSecret);
		HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
		return restTemplate
			.postForEntity(authServerUrl + "/realms/"+realm+"/protocol/openid-connect/token", entity,
					KcAccessTokenResp.class)
			.getBody();
	}

}
