package ir.mojir.my_kc_auth_client.dtos;

public class KcCreateClientReq {
    private String clientId;
    private boolean enabled;
    private boolean publicClient;
    private String protocol;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isPublicClient() {
        return publicClient;
    }

    public void setPublicClient(boolean publicClient) {
        this.publicClient = publicClient;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }
}
