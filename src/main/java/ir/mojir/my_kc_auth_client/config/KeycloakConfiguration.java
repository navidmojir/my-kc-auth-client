package ir.mojir.my_kc_auth_client.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakConfiguration {
    @Value("${kc.realm:cbi}")
    private String kcRealm;

    @Value("${kc.authServerUrl:http://localhost:8080}")
    private String authServerUrl;

    @Value("${kc.clientId:admin-cli}")
    private String clientId;

    @Value("${kc.clientSecret:}")
    private String clientSecret;

    @Value("${kc.clientUuid:}")
    private String clientUuid;

    @Value("${kc.tmpAdminUsername:tmpadmin}")
    private String tmpAdminUsername;

    @Value("${kc.tmpAdminPassword:tmpadmin}")
    private String tmpAdminPassword;

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
        return clientSecret;
    }

    public String getClientUuid() {
        return clientUuid;
    }

    public String getTmpAdminUsername() {
        return tmpAdminUsername;
    }

    public String getTmpAdminPassword() {
        return tmpAdminPassword;
    }
}
