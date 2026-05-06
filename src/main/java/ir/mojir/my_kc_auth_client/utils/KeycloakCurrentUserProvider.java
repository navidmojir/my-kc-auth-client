package ir.mojir.my_kc_auth_client.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ir.mojir.spring_boot_commons.interfaces.CurrentUserProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import ir.mojir.my_kc_auth_client.config.KeycloakConfiguration;
import ir.mojir.my_kc_auth_client.dtos.KcGetUsersInClientRoleRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcUserDetails;
import ir.mojir.my_kc_auth_client.external.KeycloakClient;
import ir.mojir.my_kc_auth_client.logic.UsersCache;

@Component
public class KeycloakCurrentUserProvider implements CurrentUserProvider {

    private static final Logger logger = LoggerFactory.getLogger(KeycloakCurrentUserProvider.class);
    @Autowired
    private KeycloakClient keycloakClient;

    @Autowired
    private KeycloakConfiguration kcConfig;

    public String getCurrentUserName() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt)authentication.getPrincipal();
        return (String)jwt.getClaims().get("preferred_username");
    }

    @Override
    public String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName();
    }

    @Override
    public String getCurrentAccessToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt)authentication.getPrincipal();
        return jwt.getTokenValue();
    }

    public KcUserDetails getUserDetailsById(String userId) {
        KcUserDetails cachedUser = UsersCache.getInstance().get(userId);
        if(cachedUser != null) {
            logger.info("Returning details for user with id {} from cache.", userId);
            return cachedUser;
        }
        else {
            logger.info("Getting details for user with id {} from keycloak.", userId);
            KcUserDetails userRetrievedFromKc = keycloakClient.getUserDetails(userId);
            UsersCache.getInstance().add(userId, userRetrievedFromKc);
            return userRetrievedFromKc;
        }
    }

    public KcUserDetails getCurrentUserDetails() {
        return getUserDetailsById(getCurrentUserId());
    }

    public String getUserFullName(String userId) {
        KcUserDetails user = getUserDetailsById(userId);
        return user.getFirstName() + " " + user.getLastName();
    }

    public String getCurrentUserFullName() {
        return getUserFullName(getCurrentUserId());
    }

    public List<String> getCurrentUserRoles() {
        List<String> result = new ArrayList<>();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt)authentication.getPrincipal();
        Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
        Map<String, Object> clientResourceAccess = (Map<String, Object>)resourceAccess.get(kcConfig.getClientId());
        if(clientResourceAccess == null)
            return result;
        return (List<String>)clientResourceAccess.get("roles");
    }

    public KcGetUsersInClientRoleRespRow[] getUsersInClientRole(String roleName) {
        return keycloakClient.getUsersInClientRole(roleName);
    }


    @Override
    public boolean isPoweredUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt)authentication.getPrincipal();
        return jwt.getClaimAsBoolean("powered_user");
    }
}
