package com.github.steveice10.mc.auth.service;

import com.github.steveice10.mc.auth.data.GameProfile;
import com.github.steveice10.mc.auth.exception.request.InvalidCredentialsException;
import com.github.steveice10.mc.auth.exception.request.RequestException;
import com.github.steveice10.mc.auth.exception.request.XboxRequestException;
import com.github.steveice10.mc.auth.util.HTTP;
import com.github.steveice10.mc.auth.util.MSALApplicationOptions;
import com.microsoft.aad.msal4j.*;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

// Credits to tycrek for device code auth implementation
public class MsaDeviceAuthenticationService extends AuthenticationService {
    private static final URI XBL_AUTH_ENDPOINT = URI.create("https://user.auth.xboxlive.com/user/authenticate");
    private static final URI XSTS_AUTH_ENDPOINT = URI.create("https://xsts.auth.xboxlive.com/xsts/authorize");
    private static final URI MC_LOGIN_ENDPOINT = URI.create("https://api.minecraftservices.com/authentication/login_with_xbox");
    private static final URI MC_PROFILE_ENDPOINT = URI.create("https://api.minecraftservices.com/minecraft/profile");

    private final String clientId;
    private final Set<String> scopes;
    private final PublicClientApplication app;
    private Consumer<DeviceCode> deviceCodeConsumer;
    private Date expiryDate;

    /**
     * Create a new {@link AuthenticationService} for Microsoft accounts using default options.
     * <p>
     * The default options include the "consumers" authority (see <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-client-application-configuration#authority">MSAL documentation</a>),
     * the <code>XboxLive.signin</code> scope, and a token persistence that saves/loads tokens to/from disk.
     */
    public MsaDeviceAuthenticationService(String clientId) throws IOException {
        this(clientId, new MSALApplicationOptions.Builder().build());
    }

    /**
     * Create a new {@link AuthenticationService} for Microsoft accounts using the given {@link MSALApplicationOptions}.
     * <p>
     * Anything not specified in the options will be set to the default values. For more control, use the
     * {@link MSALApplicationOptions.Builder} to set your own options.
     */
    public MsaDeviceAuthenticationService(String clientId, MSALApplicationOptions msalOptions) throws MalformedURLException {
        this(clientId, msalOptions.scopes, fixBuilderPersistence(
            PublicClientApplication.builder(clientId).authority(msalOptions.authority), msalOptions).build());
    }

    /**
     * Create a new {@link AuthenticationService} for Microsoft accounts with a custom MSAL {@link PublicClientApplication}.
     * <p>
     * This constructor is most useful if you need more granular control over the MSAL client on top of the provided
     * configurable options. Please note that the {@link PublicClientApplication} must be configured with the same client
     * ID as this service.
     * <p>
     * For more information on how to configure MSAL, see <a href="https://github.com/AzureAD/microsoft-authentication-library-for-java/wiki/Client-Applications">MSAL for Java documentation</a>.
     */
    public MsaDeviceAuthenticationService(String clientId, Set<String> scopes, PublicClientApplication app) {
        super(URI.create(""));

        if (clientId.isEmpty())
            throw new IllegalArgumentException("clientId cannot be null or empty.");

        this.clientId = clientId;
        this.scopes = scopes;
        this.app = app;
    }

    /**
     * Assists in creating a {@link PublicClientApplication.Builder} in one of the constructors.
     * <p>
     * Due to the nature of Builders and how MSAL handles null values, we need to do some extra work to ensure that
     * persistence is set correctly.
     */
    private static PublicClientApplication.Builder fixBuilderPersistence(PublicClientApplication.Builder builder, MSALApplicationOptions options) {
        // Set the token persistence, if specified. Necessary step as we cannot pass null to MSAL.
        if (options.tokenPersistence != null)
            builder.setTokenCacheAccessAspect(options.tokenPersistence);
        return builder;
    }

    /**
     * Sets the function to run when a <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code">Device Code flow</a> is requested.
     * <p>
     * The provided <code>consumer</code> will be called when Azure is ready for the user to authenticate. Your consumer
     * should somehow get the user to authenticate with the provided URL and user code. How this is implemented is up to
     * you. MSAL automatically handles waiting for the user to authenticate.
     *
     * @param consumer To be called when Azure wants the user to sign in. This involves showing the user the URL to open and the code to enter.
     */
    public void setDeviceCodeConsumer(Consumer<DeviceCode> consumer) {
        this.deviceCodeConsumer = consumer;
    }

    /**
     * Get an <code>IAccount</code> from the cache (if available). If only one account is available, it will be returned, regardless of which account is requested.
     *
     * @return An <code>IAccount</code> matching the username given to this <code>MSALAuthenticationService</code>. Otherwise, null.
     */
    public IAccount getIAccount() {
        return this.app.getAccounts().join().size() == 1
            ? this.app.getAccounts().join().stream().findFirst().get()
            : this.app.getAccounts().join().stream()
            .filter(account -> account.username().equalsIgnoreCase(getUsername()))
            .findFirst().orElse(null);
    }

    /**
     * Get an access token from MSAL using Device Code flow authentication.
     */
    private CompletableFuture<IAuthenticationResult> getMsalAccessToken() throws MalformedURLException {
        if (this.deviceCodeConsumer == null)
            throw new IllegalStateException("Device code consumer is not set.");

        IAccount account = this.getIAccount();
        return (account == null)
            ? this.app.acquireToken(DeviceCodeFlowParameters.builder(this.scopes, this.deviceCodeConsumer).build())
            : this.app.acquireTokenSilently(SilentParameters.builder(this.scopes, account).build());
    }

    /**
     * Get a Minecraft login response from the given Microsoft access token
     */
    private McLoginResponse getLoginResponseFromToken(String accessToken) throws RequestException {
        XblAuthResponse response = HTTP.makeRequest(getProxy(), XBL_AUTH_ENDPOINT, new XblAuthRequest(accessToken), XblAuthResponse.class);
        response = HTTP.makeRequest(getProxy(), XSTS_AUTH_ENDPOINT, new XstsAuthRequest(response.Token), XblAuthResponse.class);

        if (response.XErr != 0)
            switch ((int) (response.XErr - 2148916230L)) {
                case 3 -> throw new XboxRequestException("Microsoft account does not have an Xbox Live account attached!");
                case 5 -> throw new XboxRequestException("Xbox Live is not available in your country!");
                case 8 -> throw new XboxRequestException("This account is a child account! Please add it to a family in order to log in.");
                default -> throw new XboxRequestException(String.format("Error occurred while authenticating to Xbox Live! Error ID: %s", response.XErr));
            }

        return HTTP.makeRequest(getProxy(), MC_LOGIN_ENDPOINT, new McLoginRequest(response.DisplayClaims.xui[0].uhs, response.Token), McLoginResponse.class);
    }

    /**
     * Finalizes the authentication process using Xbox API's.
     */
    private void getProfile() throws RequestException {
        var response = HTTP.makeRequest(getProxy(),
                                        MC_PROFILE_ENDPOINT,
                                        null,
                                        McProfileResponse.class,
                                        Collections.singletonMap("Authorization", "Bearer ".concat(this.accessToken)));

        if (response == null) throw new RequestException("Invalid response received.");
        this.selectedProfile = new GameProfile(response.id, response.name);
        this.profiles = Collections.singletonList(this.selectedProfile);
    }

    @Override
    public void login() throws RequestException {
        try {
            // Complain if the username or password are set, we can do this interactively.
            if ((this.username != null && !this.username.isEmpty()) || (this.password != null && !this.password.isEmpty()))
                throw new InvalidCredentialsException("Username and password are not required for this authentication service.");

            // Complain if the consumer is not set.
            if (this.deviceCodeConsumer == null)
                throw new IllegalStateException("Device code consumer is not set.");

            // Try to log in to the users account
            IAuthenticationResult msalAuthResult = getMsalAccessToken().get();
            this.expiryDate = msalAuthResult.expiresOnDate();
            var response = getLoginResponseFromToken("d=".concat(msalAuthResult.accessToken()));
            if (response == null) throw new RequestException("Invalid response received.");
            this.accessToken = response.access_token;

            // Get the profile to complete the login process
            getProfile();

            this.loggedIn = true;
        } catch (MalformedURLException | ExecutionException | InterruptedException ex) {
            throw new RequestException(ex);
        }
    }

    public void refreshMsalToken() throws RequestException {
        try {
            if (!this.loggedIn) throw new RequestException("Not logged in");
            IAccount account = this.getIAccount();
            if (account == null) return;
            IAuthenticationResult msalAuthResult = this.app.acquireTokenSilently(SilentParameters.builder(this.scopes,
                                                                                                                 account)
                                                                                            .build()).get();
            this.expiryDate = msalAuthResult.expiresOnDate();
            var response = getLoginResponseFromToken(msalAuthResult.accessToken());
            if (response == null) throw new RequestException("Invalid response received.");
            this.accessToken = response.access_token;
            getProfile();
        } catch (MalformedURLException | InterruptedException | ExecutionException ex) {
            throw new RequestException(ex);
        }
    }

    public Optional<Date> getExpiryDate() {
        return Optional.ofNullable(this.expiryDate);
    }

    @Override
    public String toString() {
        return "MsaAuthenticationService{" +
            "clientId='" + this.clientId + '\'' +
            ", loggedIn=" + this.loggedIn +
            '}';
    }

    //#region Requests
    @SuppressWarnings({"unused", "FieldCanBeLocal"})
    private static class XblAuthRequest {
        private final String RelyingParty = "http://auth.xboxlive.com";
        private final String TokenType = "JWT";
        private final Properties Properties;

        protected XblAuthRequest(String accessToken) {
            this.Properties = new Properties(accessToken);
        }


        private static class Properties {
            private final String AuthMethod = "RPS";
            private final String SiteName = "user.auth.xboxlive.com";
            private final String RpsTicket;

            private Properties(final String rpsTicket) {
                RpsTicket = rpsTicket;
            }
        }
    }

    @SuppressWarnings({"unused", "FieldCanBeLocal"})
    private static class XstsAuthRequest {
        private final String RelyingParty = "rp://api.minecraftservices.com/";
        private final String TokenType = "JWT";
        private final Properties Properties;

        protected XstsAuthRequest(String token) {
            this.Properties = new Properties(token);
        }

        private static class Properties {
            private final String[] UserTokens;
            private final String SandboxId = "RETAIL";

            protected Properties(String token) {
                this.UserTokens = new String[]{token};
            }
        }
    }

    @SuppressWarnings({"unused", "FieldCanBeLocal"})
    private static class McLoginRequest {
        private final String identityToken;

        protected McLoginRequest(String uhs, String identityToken) {
            this.identityToken = String.format("XBL3.0 x=%s;%s", uhs, identityToken);
        }
    }
    //#endregion

    //#region Responses
    @SuppressWarnings("unused")
    private static class XblAuthResponse {
        /* Only appear in error responses */
        public String Identity;
        public long XErr;
        public String Message;
        public String Redirect;

        public String IssueInstant;
        public String NotAfter;
        public String Token;
        public DisplayClaims DisplayClaims;

        private static class DisplayClaims {
            public Xui[] xui;
        }

        private static class Xui {
            public String uhs;
        }
    }

    @SuppressWarnings("unused")
    public static class McLoginResponse {
        public String username;
        public String[] roles;
        public String access_token;
        public String token_type;
        public int expires_in;
    }

    @SuppressWarnings("unused")
    public static class McProfileResponse {
        public UUID id;
        public String name;
        public Skin[] skins;
        //public String capes; // Not sure on the datatype or response

        private static class Skin {
            public UUID id;
            public String state;
            public URI url;
            public String variant;
            public String alias;
        }
    }
    //#endregion
}
