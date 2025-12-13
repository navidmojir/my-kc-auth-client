package ir.mojir.my_kc_auth_client.config;

import java.io.File;
import java.io.IOException;
import java.util.Map;

import ir.mojir.my_kc_auth_client.dtos.InitializationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;

import ir.mojir.spring_boot_commons.helpers.Validations;

@Configuration
public class KeycloakConfiguration {
    private static final String FILE_PATH = "keycloak-client-info.json";

    private static final Logger logger = LoggerFactory.getLogger(KeycloakConfiguration.class);
    @Value("${kc.realm:cbi}")
    private String kcRealm;

    @Value("${kc.authServerUrl:http://localhost:8080}")
    private String authServerUrl;

    @Value("${kc.clientId:}")
    private String clientId;

    @Value("${kc.wuiClientId:}")
    private String wuiClientId;
    
    @Value("${kc.wuiClientRootUrl:http://localhost:4200}")
    private String wuiClientRootUrl;
    
    @Value("${kc.clientSecret:}")
    private String clientSecret;

    @Value("${kc.clientUuid:}")
    private String clientUuid;

    @Value("${kc.tmpAdminUsername:tmpadmin}")
    private String tmpAdminUsername;

    @Value("${kc.tmpAdminPassword:tmpadmin}")
    private String tmpAdminPassword;

    @Value("${kc.adminUsername:admin}")
    private String adminUsername;

    @Value("${kc.adminPassword:admin}")
    private String adminPassword;
    
    @Value("${kc.stsAdminUsername:stsadmin}")
    private String stsAdminUsername;

    @Value("${kc.stsAdminPassword:stsadmin}")
    private String stsAdminPassword;

    @Value("${kc.initializeKcAdminUser:true}")
    private boolean initializeKcAdminUser;

    @Value("${kc.initializeRealmAndClients:false}")
    private boolean initializeRealmAndClients;

    @Value("${kc.externalConfigFilePath:}")
    private String externalConfigFilePath;

    public String getExternalConfigFilePath() {
        return externalConfigFilePath;
    }

    public String getKcRealm() {
        return kcRealm;
    }

    public String getAuthServerUrl() {
        return authServerUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        loadClientUuidAndSecretFromFile();
        return clientSecret;
    }

    public String getClientUuid() {
        loadClientUuidAndSecretFromFile();
        return clientUuid;
    }

    private void loadClientUuidAndSecretFromFile() {
        if(!Validations.isBlank(getExternalConfigFilePath()))
            loadClientUuidAndSecretFromExternalFile();
        else
            loadClientUuidAndSecretFromLocalFile();
    }

    public String getTmpAdminUsername() {
        return tmpAdminUsername;
    }

    public String getTmpAdminPassword() {
        return tmpAdminPassword;
    }

    public String getWuiClientId() {
        return wuiClientId;
    }

    /**
     * If a file with FILE_PATH exists, It's priority is higher than application properties
     */
    private void loadClientUuidAndSecretFromLocalFile() {
        if(!Validations.isBlank(clientUuid) && !Validations.isBlank(clientSecret)) {
            return;
        }
        File file = new File(FILE_PATH);
        if (!file.exists()) {
            logger.info("File {} does not exists. So load client uuid and secret from application properties.", FILE_PATH);
            return;
        }

        try {
            Map<String, String> result = new ObjectMapper().readValue(file, Map.class);
            clientUuid = result.get("clientUuid");
            clientSecret = result.get("clientSecret");
            logger.info("Client UUID and Secret was loaded from file");
        } catch (IOException e) {
            logger.info("Failed to load client uuid and secret from file {}. So falling back to application properties", FILE_PATH, e);
        }
    }

    private void loadClientUuidAndSecretFromExternalFile() {
        if(!Validations.isBlank(clientUuid) && !Validations.isBlank(clientSecret)) {
            return;
        }
        File file = new File(getExternalConfigFilePath());
        if (!file.exists()) {
            logger.info("File {} does not exists.", FILE_PATH);
            return;
        }

        try {
            InitializationResult result = new ObjectMapper().readValue(file, InitializationResult.class);
            for(InitializationResult.ClientCreationResult clientInfo: result.getCreatedClients()) {
                logger.info(clientInfo.getClientId());
                if(clientInfo.getClientId().equals(getClientId())) {
                    clientUuid = clientInfo.getClientUuid();
                    clientSecret = clientInfo.getClientSecret();
                    logger.info("Client UUID and Secret was loaded from external file {}", getExternalConfigFilePath());
                    return;
                }
            }
            throw new RuntimeException(String.format("Failed to load client uuid and secret from external file %s because no matching client id (%s) found",
                    getExternalConfigFilePath(), getClientId()));
        } catch (IOException e) {
            logger.info("IOException occured while reading value from file {}. So falling back to application properties",
                    getExternalConfigFilePath(), e);
        }
    }

    public String getAdminUsername() {
        return adminUsername;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

	public String getWuiClientRootUrl() {
		return wuiClientRootUrl;
	}

	public String getStsAdminUsername() {
		return stsAdminUsername;
	}

	public String getStsAdminPassword() {
		return stsAdminPassword;
	}

    public boolean isInitializeRealmAndClients() {
        return initializeRealmAndClients;
    }

    public void setKcRealm(String kcRealm) {
        this.kcRealm = kcRealm;
    }

    public void setAuthServerUrl(String authServerUrl) {
        this.authServerUrl = authServerUrl;
    }

}
