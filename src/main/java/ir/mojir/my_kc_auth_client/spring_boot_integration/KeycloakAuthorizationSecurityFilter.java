package ir.mojir.my_kc_auth_client.spring_boot_integration;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import ir.mojir.my_kc_auth_client.exceptions.KeycloakAuthorizationClientException;
import ir.mojir.my_kc_auth_client.logic.KeycloakAuthorizationFilterLogic;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class KeycloakAuthorizationSecurityFilter extends GenericFilterBean {

	private final static Logger logger = LoggerFactory.getLogger(KeycloakAuthorizationSecurityFilter.class);

	@Autowired
	private KeycloakAuthorizationFilterLogic filterLogic;
	
//	public KeycloakAuthorizationSecurityFilter(String kcRealm,
//			String kcAuthServerUrl,
//			String kcClientId,
//			String kcClientSecret) {
//		filterLogic = new KeycloakAuthorizationFilterLogic();
//		filterLogic.initialize(kcRealm,
//				kcAuthServerUrl,
//				kcClientId,
//				kcClientSecret);
//	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletResponse httpResponse = (HttpServletResponse)response;
		try {
			
			filterLogic.authorize((HttpServletRequest)request, (HttpServletResponse)response);
		} catch(AccessDeniedException e) {
			httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
			return;
		} catch(KeycloakAuthorizationClientException e) {
			logger.error("An error occured in keycloak authorization security filter. Trace: ", e);
//			((HttpServletResponse)response).sendError(500, e.getError().getMessage());
			httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			httpResponse.getWriter().write("An exception occured while authorizing request with keycloak");
			return;
		}
		chain.doFilter(request, response);
		
	}

}
