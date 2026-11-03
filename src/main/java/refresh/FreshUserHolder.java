package com.example.authserver.refresh;

import com.example.authserver.directory.UserInfo;

/**
 * Hands the user record just re-read from the directory to the token claims customizer, which runs deeper inside the
 * framework during the same request on the same thread. Always cleared in a finally block.
 */
public final class FreshUserHolder {

    private static final ThreadLocal<UserInfo> CURRENT = new ThreadLocal<>();

    private FreshUserHolder() {
    }

    public static void set(UserInfo user) {
        CURRENT.set(user);
    }

    public static UserInfo get() {
        return CURRENT.get();
    }

    public static void clear() {
        CURRENT.remove();
    }
}
