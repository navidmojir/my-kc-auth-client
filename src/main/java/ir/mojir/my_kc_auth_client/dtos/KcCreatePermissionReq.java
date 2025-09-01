package ir.mojir.my_kc_auth_client.dtos;

public class KcCreatePermissionReq {
    private String decisionStrategy;
    private String name;
    private String[] policies;
    private String[] resources;
    private String[] scopes;

    public String getDecisionStrategy() {
        return decisionStrategy;
    }

    public void setDecisionStrategy(String decisionStrategy) {
        this.decisionStrategy = decisionStrategy;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String[] getPolicies() {
        return policies;
    }

    public void setPolicies(String[] policies) {
        this.policies = policies;
    }

    public String[] getResources() {
        return resources;
    }

    public void setResources(String[] resources) {
        this.resources = resources;
    }

    public String[] getScopes() {
        return scopes;
    }

    public void setScopes(String[] scopes) {
        this.scopes = scopes;
    }
}
