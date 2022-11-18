package com.github.steveice10.mc.auth.service;

import com.github.steveice10.mc.auth.data.GameProfile;
import fr.litarvan.openauth.microsoft.MicrosoftAuthResult;
import fr.litarvan.openauth.microsoft.MicrosoftAuthenticationException;
import fr.litarvan.openauth.microsoft.MicrosoftAuthenticator;
import fr.litarvan.openauth.microsoft.model.response.MinecraftProfile;

import java.net.URI;
import java.util.Collections;

import static java.util.Objects.isNull;

/**
 * Delegates Microsoft auth to OpenAuth lib
 */
public class MsaAuthenticationService extends AuthenticationService {
    private String refreshToken;
    // delegate
    protected final MicrosoftAuthenticator microsoftAuthenticator;

    public MsaAuthenticationService() {
        super(URI.create(""));
        this.microsoftAuthenticator = new MicrosoftAuthenticator();
    }

    @Override
    public void login() throws MicrosoftAuthenticationException {
        final MicrosoftAuthResult microsoftAuthResult = auth();
        this.accessToken = microsoftAuthResult.getAccessToken();
        MinecraftProfile profile = microsoftAuthResult.getProfile();
        this.selectedProfile = new GameProfile(profile.getId().replaceFirst(
                "(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)", "$1-$2-$3-$4-$5"
        ), profile.getName());
        this.profiles = Collections.singletonList(this.selectedProfile);
        this.username = profile.getName();
        this.refreshToken = microsoftAuthResult.getRefreshToken();
    }

    private MicrosoftAuthResult auth() throws MicrosoftAuthenticationException {
        if (isNull(refreshToken)) {
            return authWithCredentials();
        } else {
            try {
                return authWithRefreshToken();
            } catch (final Exception e) {
                return authWithCredentials();
            }
        }
    }

    private MicrosoftAuthResult authWithCredentials() throws MicrosoftAuthenticationException {
        return microsoftAuthenticator.loginWithCredentials(this.username, this.password);
    }

    private MicrosoftAuthResult authWithRefreshToken() throws MicrosoftAuthenticationException {
        return microsoftAuthenticator.loginWithRefreshToken(refreshToken);
    }
}
