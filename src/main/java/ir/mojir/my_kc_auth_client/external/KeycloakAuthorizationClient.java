package ir.mojir.my_kc_auth_client.external;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import ir.mojir.my_kc_auth_client.config.KeycloakConfiguration;
import jakarta.annotation.PostConstruct;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.resource.ProtectedResource;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ir.mojir.my_kc_auth_client.exceptions.KeycloakAuthorizationClientException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class KeycloakAuthorizationClient {

	private final static Logger logger = LoggerFactory.getLogger(KeycloakAuthorizationClient.class);
	
	private Configuration config = new Configuration();
	
//	public KeycloakAuthorizationClient(String realm, String authServerUrl, String clientId, String clientSecret) {
//		config.setRealm(realm);
//		config.setAuthServerUrl(authServerUrl);
//		config.setResource(clientId);
//		Map<String, Object> cred = new HashMap<>();
//		cred.put("secret", clientSecret);
//		config.setCredentials(cred);
//	}

	@Autowired
	private KeycloakConfiguration params;

	@PostConstruct
	private void initConfig() {
		config.setRealm(params.getKcRealm());
		config.setAuthServerUrl(params.getAuthServerUrl());
		config.setResource(params.getClientId());
		Map<String, Object> cred = new HashMap<>();
		cred.put("secret", params.getClientSecret());
		config.setCredentials(cred);

		logger.info("Keycloak config initialized with realm {}, authServerUrl: {}, clientId: {}",
				params.getKcRealm(), params.getAuthServerUrl(), params.getClientId());
	}
	
	public boolean authorize(String accessToken, String path, String method) {
		
		
		AuthzClient authzClient = AuthzClient.create(config);
		
		AuthorizationRequest req = new AuthorizationRequest();
		req.addPermission(path,  method);
		try {
			authzClient.authorization(accessToken).authorize(req);
			return true;
		} 
		catch(AuthorizationDeniedException e) {
			return false;
		}
		catch(RuntimeException e) {
			if(e.getCause() != null && e.getCause() instanceof HttpResponseException) {
				HttpResponseException re = (HttpResponseException)e.getCause();
				String responseFromKeycloak = new String(re.getBytes());
				throw new KeycloakAuthorizationClientException("response from authorization server" + responseFromKeycloak, re);
			}
			else
				throw new KeycloakAuthorizationClientException("A runtime exception occured while authorizing request", e);
		} catch(Exception e) {
			throw new KeycloakAuthorizationClientException("Failed to authorize request (general exception)", e);
		}
		
	}
	
	public void createResource(String path, String method) {
		logger.info("Attempting to create resource with path {} and method {} on keycloak", path, method);
		AuthzClient authzClient = AuthzClient.create(config);
		ResourceRepresentation newResource = new ResourceRepresentation();
		newResource.setName(path);
		newResource.setDisplayName(path);
		newResource.setUris(Collections.singleton(path));
		newResource.addScope(new ScopeRepresentation(method));
		
		ProtectedResource resourceClient = authzClient.protection().resource();
		ResourceRepresentation existingResource = resourceClient.findByName(path);
		if(existingResource != null) {
			logger.info("path {} exists. So nothing to do...", path);
			return;
		}
		
		ResourceRepresentation response = resourceClient.create(newResource);
		logger.info("resource with id {} and name {} and method {} was created on keycloak successfully", 
				response.getId(),
				response.getName(),
				method);
		
	}
}
