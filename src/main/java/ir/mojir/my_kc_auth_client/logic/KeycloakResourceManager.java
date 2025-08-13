package ir.mojir.my_kc_auth_client.logic;

import java.util.Map;
import java.util.Optional;

import ir.mojir.my_kc_auth_client.dtos.KcCreateResourceResp;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import ir.mojir.my_kc_auth_client.external.KeycloakAuthorizationClient;

@Component
public class KeycloakResourceManager {

	private final static Logger logger = LoggerFactory.getLogger(KeycloakResourceManager.class);
	
	@Autowired
	private ApplicationContext applicationContext;
	
	@Autowired
	private KeycloakAuthorizationClient client;
	
	@PostConstruct
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
			String [] searchResult = client.searchResources(path, method);
			if(searchResult.length > 0) {
				logger.info("Resource with path {} and method {} exists. So continue...", path, method);
				ClientResourcesCache.getInstance().put(path, method, searchResult[0]);
				continue;
			}
			KcCreateResourceResp resp = client.createResource(path, method);
			ClientResourcesCache.getInstance().put(path, method, resp.get_id());
			logger.info("Resource with path {} and method {} was created successfully with id {}",
					path, method, resp.get_id());
		}
	}

}
