package com.example.authserver.directory;

import java.util.Set;

/** A user as known by an application's own directory. {@code userId} is the app's own identifier. */
public record UserInfo(String userId, String displayName, Set<String> roles, boolean active) {

    public UserInfo {
        displayName = (displayName == null || displayName.isBlank()) ? userId : displayName;
        roles = roles == null ? Set.of() : Set.copyOf(roles);
    }
}
