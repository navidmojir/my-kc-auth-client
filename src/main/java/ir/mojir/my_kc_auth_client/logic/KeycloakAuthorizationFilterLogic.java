package ir.mojir.my_kc_auth_client.logic;

import java.io.IOException;
import java.nio.file.AccessDeniedException;

import ir.mojir.my_kc_auth_client.exceptions.KeycloakAuthorizationClientException;
import ir.mojir.my_kc_auth_client.external.KeycloakAuthorizationClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//@Component
public class KeycloakAuthorizationFilterLogic {
//	@Autowired
//	private ParameterService params;
	
	private KeycloakAuthorizationClient client = null;
	
	
//	@PostConstruct
//	private void init() {
//		client = new KeycloakAuthorizationClient(
//				params.getKcRealm(),
//				params.getKcAuthServerUrl(),
//				params.getKcClientId(),
//				params.getKcClientSecret());
//	}
//	
	
	public void initialize(String kcRealm, String kcAuthServerUrl, String kcClientId, String kcClientSecret) {
		client = new KeycloakAuthorizationClient(
			kcRealm,
			kcAuthServerUrl,
			kcClientId,
			kcClientSecret);
	}
	
	public void authorize(HttpServletRequest req, HttpServletResponse resp) throws IOException, KeycloakAuthorizationClientException {
		
		if(client == null)
			throw new KeycloakAuthorizationClientException("initialize method must be called first", null);
		
		String accessToken = req.getHeader("Authorization").replaceAll("(?i)bearer ", "");
			
		boolean authorized = client.authorize(accessToken,
				req.getRequestURI(), req.getMethod());
		
		if(!authorized)
			throw new AccessDeniedException("403");
		
	}
}
