package ir.mojir.my_kc_auth_client.logic;

import ir.mojir.my_kc_auth_client.dtos.KcUserDetails;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class UsersCache {
    private static UsersCache instance = null;
    private UsersCache(){
        map = new HashMap<>();
    }

    private Map<String, KcUserDetails> map;

    public static UsersCache getInstance() {
        if(instance == null)
            instance = new UsersCache();
        return instance;
    }

    public void add(String userId, KcUserDetails kcUserDetails) {
        map.put(userId, kcUserDetails);
    }

    public KcUserDetails get(String userId) {
        KcUserDetails entry = map.get(userId);
        if(entry == null)
            return null;
        if(isOlderThan15Minutes(entry.getRetrievalTime())) {
            map.remove(userId);
            return null;
        }
        return entry;
    }

    private boolean isOlderThan15Minutes(Date date) {
        LocalDateTime dateLDT = LocalDateTime.ofInstant(date.toInstant(), ZoneId.systemDefault());
        Duration duration = Duration.between(dateLDT, LocalDateTime.now());
        long durationMinutes = duration.toMinutes();
        if(durationMinutes > 1)
            return true;
        else
            return false;
    }


}
