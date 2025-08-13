package ir.mojir.my_kc_auth_client.logic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ClientResourcesCache {

    private final static Logger logger = LoggerFactory.getLogger(ClientResourcesCache.class);
    /**
     * map from url#scope to id
     */
    private Map<String, String> map = new HashMap<>();
    private ClientResourcesCache() {}

    private static ClientResourcesCache instance = null;

    public static ClientResourcesCache getInstance() {
        if(instance == null)
            instance = new ClientResourcesCache();
        return instance;
    }

    public void put(String path, String method, String id) {
        map.put(path + "#" + method, id);
        logger.trace("Cache entry {}#{}->{} was added", path, method, id);
    }

    public String get(String path, String method) {
        logger.trace("Getting cache entry {}#{}", path, method);
        return map.get(path + "#" + method);
    }

}
