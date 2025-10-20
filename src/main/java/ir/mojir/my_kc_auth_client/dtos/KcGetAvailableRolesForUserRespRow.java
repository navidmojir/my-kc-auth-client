package ir.mojir.my_kc_auth_client.dtos;

public class KcGetAvailableRolesForUserRespRow {
    private String id;
    private String clientId;

    private String role;
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
