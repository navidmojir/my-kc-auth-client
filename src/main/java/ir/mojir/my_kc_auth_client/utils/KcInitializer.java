package ir.mojir.my_kc_auth_client.utils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import ir.mojir.my_kc_auth_client.config.KeycloakConfiguration;
import ir.mojir.my_kc_auth_client.dtos.KcAssignRoleToUserReqRow;
import ir.mojir.my_kc_auth_client.dtos.KcCreateAuthorizationPolicyReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreateClientReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreateClientRoleReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreatePermissionReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreateRealmReq;
import ir.mojir.my_kc_auth_client.dtos.KcCreateUserReq;
import ir.mojir.my_kc_auth_client.dtos.KcGetAllClientAuthorizationPoliciesRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcGetAvailableClientRolesForUserRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcGetAvailableRealmRolesForUserRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcGetClientResp;
import ir.mojir.my_kc_auth_client.dtos.KcGetPermissionResp;
import ir.mojir.my_kc_auth_client.dtos.KcGetPolicyResp;
import ir.mojir.my_kc_auth_client.dtos.KcGetServiceAccountUserIdResp;
import ir.mojir.my_kc_auth_client.dtos.KcResetPasswordReq;
import ir.mojir.my_kc_auth_client.dtos.KcSearchClientRoleRespRow;
import ir.mojir.my_kc_auth_client.dtos.KcSearchUserRespRow;
import ir.mojir.my_kc_auth_client.external.KeycloakClient;
import ir.mojir.my_kc_auth_client.logic.ClientResourcesCache;
import ir.mojir.my_kc_auth_client.logic.KeycloakResourceManager;
import ir.mojir.spring_boot_commons.exceptions.InternalErrorException;
import ir.mojir.spring_boot_commons.helpers.Validations;

@Component
public class KcInitializer {

    private static final Logger logger = LoggerFactory.getLogger(KcInitializer.class);

    private static final String FILE_PATH = "keycloak-client-info.json";

    @Autowired
    private KeycloakClient keycloakClient;

    @Autowired
    private KeycloakConfiguration kcConfig;

    private String adminAccessToken = null;

    @Autowired
    private KeycloakResourceManager keycloakResourceManager;

    @Autowired
    @Qualifier(value = "myRoleResolver")
    private RoleResolver roleResolver;
    
    private String[] defaultAdminRoles;
    private String[] allRoles;

//    @PostConstruct
    public void init() {
        logger.info("Trying to configure keycloak at url {} with realm name {}", kcConfig.getAuthServerUrl(),
                kcConfig.getKcRealm());
        if(kcConfig.isInitializeRealmAndClients()) {
            logger.info("initializing realm and clients");
            adminAccessToken = fetchAdminAccessToken();
            if (!Validations.isBlank(adminAccessToken)) {
                createRealm();
                createApiClient();
                createWuiClient();
                assignNeededRolesToApiClient();
                createClientRolesInKeycloak();
                createUser();
                if (kcConfig.isInitializeKcAdminUser()) {
                    createAdminUser();
                    removeTmpAdminUser();
                }
            }
        }

        createAllResources();
        createPoliciesInKeycloak();
        createPermissionsInKeycloak();
    }

    private void createUser() {
        if(keycloakClient.isUserExists(kcConfig.getStsAdminUsername(), kcConfig.getKcRealm(), adminAccessToken)) {
            logger.trace("User with name {} already exists. So skipping user creation.", kcConfig.getStsAdminUsername());
            return;
        }
    	KcCreateUserReq req = new KcCreateUserReq();
        req.setUsername(kcConfig.getStsAdminUsername());
        req.setEnabled(true);
        String userId = keycloakClient.createUser(kcConfig.getKcRealm(), req, adminAccessToken);
        logger.info("user {} was created on keycloak.", kcConfig.getStsAdminUsername());

        KcResetPasswordReq resetReq = new KcResetPasswordReq();
        resetReq.setTemporary(false);
        resetReq.setType("password");
        resetReq.setValue(kcConfig.getStsAdminPassword());
        keycloakClient.resetAdminPassword(kcConfig.getKcRealm(), userId, resetReq, adminAccessToken);
        logger.info("Password was successfully set for user {}.", kcConfig.getStsAdminUsername());

        if(defaultAdminRoles != null)
        	for(String userRole: defaultAdminRoles)
        		assignClientRoleToUser(userId, userRole);
		
	}


	public void setDefaultAdminRoles(String[] defaultAdminRoles) {
		this.defaultAdminRoles = defaultAdminRoles;
	}

	private void assignClientRoleToUser(String userId, String role) {
        KcGetAvailableClientRolesForUserRespRow[] availableRoles = keycloakClient.getAvailableClientRolesForUser(
                userId, adminAccessToken, role
        );
        if(availableRoles == null || availableRoles.length == 0)
            throw new InternalErrorException("Failed to find "+role+" client role in order to assign it", null);
        KcAssignRoleToUserReqRow assignRoleReqRow = new KcAssignRoleToUserReqRow();
        for(KcGetAvailableClientRolesForUserRespRow row: availableRoles) {
            if(row.getRole().equals(role)) {
                assignRoleReqRow.setId(row.getId());
                assignRoleReqRow.setName(row.getRole());
            }
        }
        KcAssignRoleToUserReqRow[] assignRoleReq = { assignRoleReqRow };
        keycloakClient.assignClientRoleToUser(userId, kcConfig.getClientUuid(), assignRoleReq, adminAccessToken);
        logger.info("Role {} was successfully assigned to user {}.", role, kcConfig.getStsAdminUsername());
    }

	private void removeTmpAdminUser() {
        logger.trace("Trying to get admin access token for new admin user with name {}", kcConfig.getAdminUsername());
        String newAdminAccessToken = keycloakClient.getAdminAccessToken(kcConfig.getAdminUsername(), kcConfig.getAdminPassword());

        logger.trace("Trying to find temp admin user with username {}", kcConfig.getTmpAdminUsername());
        KcSearchUserRespRow[] result = keycloakClient.searchUsers(kcConfig.getTmpAdminUsername(), "master", newAdminAccessToken);
        if(result == null || result.length == 0)
            throw new InternalErrorException("Failed to find temp admin user: " + kcConfig.getTmpAdminUsername(), null);
        String tmpAdminUserId = "";
        for(KcSearchUserRespRow row: result) {
            if(row.getUsername().equals(kcConfig.getTmpAdminUsername()))
                tmpAdminUserId = row.getId();
        }
        keycloakClient.deleteUser("master", tmpAdminUserId, newAdminAccessToken);
    }

    private String fetchAdminAccessToken() {
        try {
            return keycloakClient.getAdminAccessToken(
                    kcConfig.getTmpAdminUsername(), kcConfig.getTmpAdminPassword());
        } catch (Exception e) {
            logger.info("Failed to get admin access token for {}. So skipping some initializations.",
                    kcConfig.getTmpAdminUsername());
            return null;
        }
    }

    private void createAdminUser() {
        KcCreateUserReq req = new KcCreateUserReq();
        req.setUsername(kcConfig.getAdminUsername());
        req.setEnabled(true);
        String userId = keycloakClient.createUser("master", req, adminAccessToken);
        logger.info("Permanent admin user with username {} was created on keycloak.", kcConfig.getAdminUsername());

        KcResetPasswordReq resetReq = new KcResetPasswordReq();
        resetReq.setTemporary(false);
        resetReq.setType("password");
        resetReq.setValue(kcConfig.getAdminPassword());
        keycloakClient.resetAdminPassword("master", userId, resetReq, adminAccessToken);
        logger.info("Password was successfully set on permanent admin user.");

        KcGetAvailableRealmRolesForUserRespRow[] availableRoles = keycloakClient.getAvailableRealmRolesForUser(
                "master", userId, adminAccessToken, "admin"
        );
        if(availableRoles == null || availableRoles.length == 0)
            throw new InternalErrorException("Failed to find admin realm role in order to assign it", null);
        KcAssignRoleToUserReqRow assignRoleReqRow = new KcAssignRoleToUserReqRow();
        for(KcGetAvailableRealmRolesForUserRespRow row: availableRoles) {
            if(row.getName().equals("admin")) {
                assignRoleReqRow.setId(row.getId());
                assignRoleReqRow.setName(row.getName());
            }
        }
        KcAssignRoleToUserReqRow[] assignRoleReq = { assignRoleReqRow };
        keycloakClient.assignRealmRoleToUser("master", userId, assignRoleReq, adminAccessToken);
        logger.info("Role admin was successfully assigned to permanent admin user");
    }

    private void createAllResources() {
        keycloakResourceManager.createResourcesInKeycloak();
    }

    private void assignNeededRolesToApiClient() {

        assignRoleToClient("view-users");
        assignRoleToClient("view-clients");
        assignRoleToClient("manage-clients");
        assignRoleToClient("view-authorization");

        }

    private void assignRoleToClient(String roleName) {
        logger.trace("trying to assign role {} to client {}", roleName, kcConfig.getClientId());
        String clientServiceAccountUserId = getClientServiceAccountUserId();
        KcGetAvailableClientRolesForUserRespRow[] viewUsersRoleInfo = keycloakClient.getAvailableClientRolesForUser(
                clientServiceAccountUserId, adminAccessToken, roleName);
        if(viewUsersRoleInfo != null && viewUsersRoleInfo.length == 0)
        {
            logger.trace(roleName + " role is already assigned to client");
            return;
        }
        if(viewUsersRoleInfo == null || viewUsersRoleInfo.length != 1)
            throw new InternalErrorException("Failed to get information of "+roleName+" role from keycloak", null);
        KcAssignRoleToUserReqRow row = new KcAssignRoleToUserReqRow();
        row.setId(viewUsersRoleInfo[0].getId());
        row.setName(viewUsersRoleInfo[0].getRole());
        KcAssignRoleToUserReqRow[] req = { row };

        keycloakClient.assignClientRoleToUser(clientServiceAccountUserId, viewUsersRoleInfo[0].getClientId(), req, adminAccessToken);
        logger.info("role {} was successfully assigned to client", roleName);
    }

    private String getClientServiceAccountUserId() {
        KcGetServiceAccountUserIdResp resp = keycloakClient.getServiceAccountUserId(kcConfig.getClientUuid(), adminAccessToken);
        return resp.getId();
    }

    private void createApiClient() {
        KcCreateClientReq req = new KcCreateClientReq();
        req.setClientId(kcConfig.getClientId());
        req.setEnabled(true);
        req.setPublicClient(false);
        req.setProtocol("openid-connect");
        req.setServiceAccountsEnabled(true);
        req.setDirectAccessGrantsEnabled(true);
        req.setStandardFlowEnabled(false);
        req.setAuthorizationServicesEnabled(true);
        createClient(req);

        KcGetClientResp client = keycloakClient.getClient(kcConfig.getClientId(), adminAccessToken);
        String clientSecret = keycloakClient.fetchClientSecret(client.getId(), adminAccessToken);
//        logger.info("client uuid is {} and client secret is {}", client.getId(), clientSecret);
        writeClientInfoIntoFile(client.getId(), clientSecret);
    }

    private void writeClientInfoIntoFile(String clientUuid, String clientSecret) {
        Map<String, String> data = Map.of(
                "clientUuid", clientUuid,
                "clientSecret", clientSecret
        );
        try {
            new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(new File(FILE_PATH), data);
        } catch (IOException e) {
            throw new InternalErrorException("Failed to write keycloak info into file " + FILE_PATH, e);
        }
    }

    private void createWuiClient() {
//        String wuiClientId;
//        if(Validations.isBlank(kcConfig.getWuiClientId()))
//            wuiClientId = "sts-wui";
//        else
        String wuiClientId = kcConfig.getWuiClientId();
        if(Validations.isBlank(wuiClientId)){
            logger.info("Skipping creating wui client. Because its id is not configured.");
            return;
        }
        KcCreateClientReq req = new KcCreateClientReq();
        req.setClientId(wuiClientId);
        req.setEnabled(true);
        req.setPublicClient(true);
        req.setProtocol("openid-connect");
        req.setServiceAccountsEnabled(false);
        req.setDirectAccessGrantsEnabled(false);
        req.setStandardFlowEnabled(true);
        req.setAuthorizationServicesEnabled(false);
        req.setRootUrl(kcConfig.getWuiClientRootUrl());
        req.setRedirectUris(new String[] {"/*"});
        req.setWebOrigins(new String[] {"+"});
        createClient(req);
    }
    private void createClient(KcCreateClientReq req) {

        if(isClientExists(req.getClientId())) {
            logger.trace("Client with clientId {} exists. So no need for creation...", req.getClientId());
            return;
        }
        logger.trace("Trying to create client with clientId {}", req.getClientId());
        keycloakClient.createClient(req, adminAccessToken);
        logger.info("Client with clientId {} was created successfully", req.getClientId());
    }

//    private void createWuiClient() {
//        if(isClientExists())
//    }

    private boolean isClientExists(String clientId) {
        logger.trace("Checking if client with clientId {} exists", clientId);
        return keycloakClient.isClientExists(clientId, adminAccessToken);
    }

    private void createRealm() {
        if(isRealmExists()) {
            logger.trace("Realm exists. So no need for creation...");
            return;
        }
        logger.trace("Trying to create realm");

        KcCreateRealmReq req = new KcCreateRealmReq();
        req.setRealm(kcConfig.getKcRealm());
        req.setEnabled(true);
        keycloakClient.createRealm(req, adminAccessToken);

        logger.info("Realm created successfully");
    }

    private boolean isRealmExists() {
        logger.trace("Checking if realm exists");
        return keycloakClient.isRealmExists(kcConfig.getKcRealm(), adminAccessToken);
    }

    private void createPermissionsInKeycloak() {
        for(Map.Entry<String, String> entry: ClientResourcesCache.getInstance().getMap().entrySet()) {
            KcCreatePermissionReq req = new KcCreatePermissionReq();
            String key = entry.getKey();
            String[] splittedKey = key.split("#");
            String path = splittedKey[0];
            String method = splittedKey[1];
            String resourceId = entry.getValue();
            req.setDecisionStrategy("AFFIRMATIVE");
            req.setName(method + " - " + path);
            logger.trace("Trying to add permission with name {}", req.getName());
            if(isPermissionExists(req.getName())) {
                logger.trace("Permission with name {} already exists", req.getName());
                continue;
            }
            req.setResources(new String[]{resourceId});
            String[] policies = makePoliciesBasedOnAllowedRoles(method, path);
            req.setPolicies(policies);
            req.setScopes(new String[]{method});
            keycloakClient.createPermission(req);
            logger.info("Permission with name {} was created successfully", req.getName());
        }
    }

    private String[] makePoliciesBasedOnAllowedRoles(String method, String path) {
        List<String> result = new ArrayList<>();
        String[] allowedRoles = roleResolver.getAllowedRoles(method, path);
        for(String role: allowedRoles) {
            KcGetPolicyResp policy = keycloakClient.getPolicyByName(kcConfig.getClientUuid(), "role=" + role);
            if(policy == null) {
            	logger.warn("Failed to add policy for role {} on permission with method {} and path {}", role, method, path);
            	continue;
            }
            result.add(policy.getId());
        }
        return result.toArray(new String[0]);


    }

    private boolean isPermissionExists(String permissionName) {
        KcGetPermissionResp result = keycloakClient.getPermissionByName(kcConfig.getClientUuid(), permissionName);
        if(result == null)
            return false;
        return true;
    }

    private void createPoliciesInKeycloak() {
        logger.trace("Trying to create policies in keycloak");
        KcGetAllClientAuthorizationPoliciesRespRow[] currentPolicies = keycloakClient.getAllClientAuthorizationPolicies();
        for(String role: allRoles) {
            if(isPolicyExist(currentPolicies, role)) {
            	logger.info("Policy for role {} exists for client {}", role, kcConfig.getClientId());
                continue;
            }
            try {
	            KcCreateAuthorizationPolicyReq req = new KcCreateAuthorizationPolicyReq();
	            req.setName("role="+role);
	            KcCreateAuthorizationPolicyReq.Role reqRole = new KcCreateAuthorizationPolicyReq.Role();
	            reqRole.setId(getRoleId(role));
	            reqRole.setRequired(false);
	            req.setRoles(Collections.singletonList(reqRole));
	            keycloakClient.createAuthorizationPolicy(req);
	            logger.info("Authorization policy with name {} was created", req.getName());
            } catch(Exception e) {
            	logger.warn("Failed to add authorization policy for {}", role);
            	logger.debug("Trace of error is:", e);
            }
        }

    }

    private boolean isPolicyExist(KcGetAllClientAuthorizationPoliciesRespRow[] policies, String role) {
        for(KcGetAllClientAuthorizationPoliciesRespRow policy: policies) {
            if(policy.getName().equals("role=" + role))
                return true;
        }
        return false;
    }

    private String getRoleId(String roleName) {
        return keycloakClient.getClientRoleDetails(roleName).getId();
    }

    private void createClientRolesInKeycloak() {
        logger.trace("Trying to create client roles if not exists");
        KcSearchClientRoleRespRow[] clientRoles = keycloakClient.getAllClientRoles();
        for(String role: allRoles) {
            if(!roleExists(role, clientRoles)) {
                KcCreateClientRoleReq req = new KcCreateClientRoleReq();
                req.setName(role);
                keycloakClient.createClientRole(req);
                logger.info("Role with name {} created", role);
            }
        }
    }

    private boolean roleExists(String role, KcSearchClientRoleRespRow[] clientRoles) {
        for(KcSearchClientRoleRespRow kcRole: clientRoles) {
            if(kcRole.getName().equals(role))
                return true;
        }
        return false;
    }

	public void setAllRoles(String[] allRoles) {
		this.allRoles = allRoles;
	}

    

}
