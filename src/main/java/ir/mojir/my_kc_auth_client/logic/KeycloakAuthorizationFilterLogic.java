package ir.mojir.my_kc_auth_client.logic;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

import ir.mojir.my_kc_auth_client.exceptions.KeycloakAuthorizationClientException;
import ir.mojir.my_kc_auth_client.external.KeycloakAuthorizationClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

@Component
public class KeycloakAuthorizationFilterLogic {
	
	private static final Logger logger = LoggerFactory.getLogger(KeycloakAuthorizationFilterLogic.class);
	
//	@Autowired
//	private ParameterService params;

	@Autowired
	private KeycloakAuthorizationClient client;
	
	
//	@PostConstruct
//	private void init() {
//		client = new KeycloakAuthorizationClient(
//				params.getKcRealm(),
//				params.getKcAuthServerUrl(),
//				params.getKcClientId(),
//				params.getKcClientSecret());
//	}
//	
	
//	public void initialize(String kcRealm, String kcAuthServerUrl, String kcClientId, String kcClientSecret) {
//		client = new KeycloakAuthorizationClient(
//			kcRealm,
//			kcAuthServerUrl,
//			kcClientId,
//			kcClientSecret);
//	}
	
	public void authorize(HttpServletRequest req, HttpServletResponse resp) throws IOException, KeycloakAuthorizationClientException {
		
//		if(client == null)
//			throw new KeycloakAuthorizationClientException("initialize method must be called first", null);
		
		if(req.getHeader("Authorization") == null)
			throw new KeycloakAuthorizationClientException("Authorization header was not found in the request", null);
		
		String accessToken = req.getHeader("Authorization").replaceAll("(?i)bearer ", "");
		
		logger.trace("trying to authorize request with uri '{}' and method '{}' with access token '{}'", req.getRequestURI(), 
				req.getMethod(), accessToken);
		boolean authorized = client.authorize(accessToken,
				req.getRequestURI(), req.getMethod());
		
		if(!authorized)
			throw new AccessDeniedException("403");
		
	}
}
