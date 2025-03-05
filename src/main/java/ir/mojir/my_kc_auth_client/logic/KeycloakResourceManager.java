package ir.mojir.my_kc_auth_client.logic;

import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import ir.mojir.my_kc_auth_client.external.KeycloakAuthorizationClient;

//@Component
public class KeycloakResourceManager {

	private final static Logger logger = LoggerFactory.getLogger(KeycloakResourceManager.class);
	
//	@Autowired 
	private ApplicationContext applicationContext = null;
	
//	@Autowired
//	private ParameterService params;
	
	private KeycloakAuthorizationClient client = null;
	
	public void initialize(String kcRealm, String kcAuthServerUrl, String kcClientId, String kcClientSecret, ApplicationContext applicationContext) {
		this.client = new KeycloakAuthorizationClient(
			kcRealm,
			kcAuthServerUrl,
			kcClientId,
			kcClientSecret);
		
		this.applicationContext = applicationContext;
	}
	
//	@PostConstruct
//	private void init() {
//		client = new KeycloakAuthorizationClient(
//				params.getKcRealm(),
//				params.getKcAuthServerUrl(),
//				params.getKcClientId(),
//				params.getKcClientSecret());
//	}
	
//	@PostConstruct
	public void createResourcesInKeycloak() {
		
		logger.info("Trying to create resources in keycloak for the client");
		RequestMappingHandlerMapping requestMappingHandlerMapping = applicationContext
		        .getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
		    Map<RequestMappingInfo, HandlerMethod> map = requestMappingHandlerMapping
		        .getHandlerMethods();
		    for(Map.Entry<RequestMappingInfo, HandlerMethod> entry: map.entrySet()) {
		    	Optional<RequestMethod> optMethod = entry.getKey().getMethodsCondition().getMethods().stream().findFirst();
		    	if(optMethod.isEmpty())
		    		continue;
		    	String method = optMethod.get().name();
		    	String path = entry.getKey().getPathPatternsCondition().getFirstPattern().toString();
		    	client.createResource(path, method);
		    }
	}
}
