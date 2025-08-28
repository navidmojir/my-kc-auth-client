package ir.mojir.my_kc_auth_client.external;

import java.util.*;

import ir.mojir.my_kc_auth_client.config.KeycloakConfiguration;
import ir.mojir.my_kc_auth_client.dtos.*;
import ir.mojir.my_kc_auth_client.logic.ClientResourcesCache;
import ir.mojir.spring_boot_commons.exceptions.UnauthorizedException;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ir.mojir.my_kc_auth_client.exceptions.KeycloakAuthorizationClientException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Component
public class KeycloakAuthorizationClient {

	private final static Logger logger = LoggerFactory.getLogger(KeycloakAuthorizationClient.class);

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
		if(clientAccessToken != null)
			return;

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


}
