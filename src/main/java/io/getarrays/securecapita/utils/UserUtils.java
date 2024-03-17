package io.getarrays.securecapita.utils;

import io.getarrays.securecapita.domain.UserPrincipal;
import io.getarrays.securecapita.dto.UserDTO;
import org.springframework.security.core.Authentication;

public class UserUtils {
    public static UserDTO getAuthenticatedUser (Authentication authentication) {
        return ((UserDTO) authentication.getPrincipal());
    }

    public static UserDTO getLoggedInUser (Authentication authentication) {
        return ((UserPrincipal) authentication.getPrincipal()).getUser();
    }
}
