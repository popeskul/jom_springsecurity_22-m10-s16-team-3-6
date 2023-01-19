package com.softserve.itacademy.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        PersonDetails userDetails = (PersonDetails) authentication.getPrincipal();

        String redirectURL = request.getContextPath();

        if (userDetails.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ADMIN"))) {
            redirectURL += "/";
        } else {
            redirectURL += "/todos/all/users/" + userDetails.getId();
        }

        getRedirectStrategy().sendRedirect(request, response, redirectURL);
    }
}
