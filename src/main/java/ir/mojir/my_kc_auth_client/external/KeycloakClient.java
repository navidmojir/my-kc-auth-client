package ir.mojir.my_kc_auth_client.external;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ir.mojir.my_kc_auth_client.config.KeycloakConfiguration;
import ir.mojir.my_kc_auth_client.dtos.*;
import ir.mojir.my_kc_auth_client.logic.ClientResourcesCache;
import ir.mojir.spring_boot_commons.exceptions.InternalErrorException;
import ir.mojir.spring_boot_commons.exceptions.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ir.mojir.my_kc_auth_client.exceptions.KeycloakAuthorizationClientException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Component
public class KeycloakClient {

	private final static Logger logger = LoggerFactory.getLogger(KeycloakClient.class);

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

	private void getAccessTokenForClient() {
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
//		getAccessTokenForClient();
//
//		RestTemplate restTemplate = new RestTemplate();
//		HttpHeaders headers = new HttpHeaders();
//		headers.setBearerAuth(clientAccessToken);
//		HttpEntity<KcCreateClientRoleReq> entity = new HttpEntity<>(req, headers);
//		restTemplate.exchange(
//				params.getAuthServerUrl() + "/admin/realms/" + params.getKcRealm()
//						+ "/clients/" + clientUuid + "/roles",
//				HttpMethod.POST,
//				entity,
//				Void.class
//		);
		String url = String.format("/admin/realms/%s/clients/%s/roles",
				params.getKcRealm(), params.getClientUuid());

		callPost(url, req, new ParameterizedTypeReference<Void>() {});
	}

	private <REQ, RESP> RESP callPost(String url, REQ req, ParameterizedTypeReference<RESP> responseType) {
		getAccessTokenForClient();
		return callPost(url, req, responseType, clientAccessToken);
	}

	private <REQ, RESP> RESP callPost(String url, REQ req, ParameterizedTypeReference<RESP> responseType, String accessToken) {
		return callPostAsResponseEntity(url, req, responseType, accessToken).getBody();
	}
	private <REQ, RESP> ResponseEntity<RESP> callPostAsResponseEntity(String url, REQ req, ParameterizedTypeReference<RESP> responseType, String accessToken) {
		Class<RESP> respClass;

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
		Class<RESP> respClass;

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
		Class<RESP> respClass;

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
		Class<RESP> respClass;

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
//		getAccessTokenForClient();
//
//		RestTemplate restTemplate = new RestTemplate();
//		HttpHeaders headers = new HttpHeaders();
//		headers.setBearerAuth(clientAccessToken);
//		HttpEntity<String> entity = new HttpEntity<>(headers);
//		return restTemplate.exchange(params.getAuthServerUrl() + "/admin/realms/" + params.getKcRealm()
//						+ "/clients/" + params.getClientUuid() + "/roles",
//				HttpMethod.GET,
//				entity,
//				KcSearchClientRoleRespRow[].class
//		).getBody();

		String url = String.format("/admin/realms/%s/clients/%s/roles", params.getKcRealm(), params.getClientUuid());
		return callGet(url, new ParameterizedTypeReference<KcSearchClientRoleRespRow[]>() {});
	}

	public KcGetUsersInClientRoleRespRow[] getUsersInClientRole(String roleName) {
//		getAccessTokenForClient();
//
//		RestTemplate restTemplate = new RestTemplate();
//		HttpHeaders headers = new HttpHeaders();
//		headers.setBearerAuth(clientAccessToken);
//		HttpEntity<String> entity = new HttpEntity<>(headers);
//		return restTemplate.exchange(params.getAuthServerUrl() + "/admin/realms/" + params.getKcRealm()
//						+ "/clients/" + clientUuid + "/roles/" + roleName + "/users",
//				HttpMethod.GET,
//				entity,
//				KcGetUsersInClientRoleRespRow[].class
//		).getBody();

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
		String url = String.format("/admin/realms/sts/clients/%s/authz/resource-server/policy?name=%s", clientUuid, policyName);
		KcGetPolicyResp[] result = callGet(url, new ParameterizedTypeReference<KcGetPolicyResp[]>() {}, clientAccessToken);

		if(result == null || result.length != 1)
			return null;
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
		String url = String.format("/admin/realms/sts/clients/%s/authz/resource-server/permission?name=%s", clientUuid, encodedPermissionName);


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
			return result[0];
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

	public String createAdminUser(KcCreateUserReq req, String adminAccessToken) {
		String url = String.format("/admin/realms/master/users");
		ResponseEntity<Void> resp = callPostAsResponseEntity(url, req, new ParameterizedTypeReference<Void>() {},
				adminAccessToken);

		URI location = resp.getHeaders().getLocation();
		String[] locationPathParts = location.getPath().split("/");
		return locationPathParts[locationPathParts.length - 1];
	}

	public void resetAdminPassword(String userId, KcResetPasswordReq req, String adminAccessToken) {
		String url = String.format("/admin/realms/master/users/%s/reset-password", userId);
		callPutAsResponseEntity(url, req, new ParameterizedTypeReference<Void>() {}, adminAccessToken);
	}

	public void deleteUser(String realm, String userId, String adminAccessToken) {
		String url = String.format("/admin/realms/%s/users/%s", realm, userId);
		callDeleteAsResponseEntity(url, new ParameterizedTypeReference<Void>() {}, adminAccessToken);
	}

	public KcSearchUserRespRow[] searchUsers(String username, String adminAccessToken) {
		String url = String.format("/admin/realms/master/ui-ext/brute-force-user?briefRepresentation=true&search=%s", username);
		return callGet(url, new ParameterizedTypeReference<KcSearchUserRespRow[]>() {}, adminAccessToken);
	}



}
