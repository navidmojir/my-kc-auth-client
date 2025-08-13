package ir.mojir.my_kc_auth_client.dtos;

import java.util.List;

public class KcCreateResourceReq {
    private String name;
    private String displayName;

    private List<String> uris;

    private List<KcScope> resource_scopes;

    private List<KcScope> scopes;


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public List<String> getUris() {
        return uris;
    }

    public void setUris(List<String> uris) {
        this.uris = uris;
    }

    public List<KcScope> getResource_scopes() {
        return resource_scopes;
    }

    public void setResource_scopes(List<KcScope> resource_scopes) {
        this.resource_scopes = resource_scopes;
    }

    public List<KcScope> getScopes() {
        return scopes;
    }

    public void setScopes(List<KcScope> scopes) {
        this.scopes = scopes;
    }
}
