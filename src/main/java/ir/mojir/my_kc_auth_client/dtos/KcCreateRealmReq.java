package ir.mojir.my_kc_auth_client.dtos;

public class KcCreateRealmReq {
    private String realm;
    private boolean enabled;

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
