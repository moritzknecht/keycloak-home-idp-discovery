package de.sventorben.keycloak.authentication.hidpd;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import de.sventorben.keycloak.authentication.hidpd.discovery.spi.HomeIdpDiscoverer;
import java.util.List;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.WebAuthnConditionalUIAuthenticator;
import org.keycloak.models.UserModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.cookie.CookieProvider;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.theme.freemarker.FreeMarkerProvider;
import org.keycloak.tracing.TracingProvider;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class HomeIdpDiscoveryPasskeysTest {

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    AuthenticationFlowContext context;

    @Mock
    WebAuthnConditionalUIAuthenticator passkeys;

    @Mock
    AbstractHomeIdpDiscoveryAuthenticatorFactory.DiscovererConfig discovererConfig;

    private HomeIdpDiscoveryAuthenticator authenticator;

    @BeforeEach
    void setUp() {
        authenticator = new HomeIdpDiscoveryAuthenticator(discovererConfig, passkeys);
    }

    private void stubEmailForm() {
        KeycloakSession session = context.getSession();
        doReturn(mock(FreeMarkerProvider.class)).when(session).getProvider(FreeMarkerProvider.class);
        doReturn(mock(TracingProvider.class)).when(session).getProvider(TracingProvider.class);
        stubReauthentication();
    }

    private void stubReauthentication() {
        KeycloakSession session = context.getSession();
        doReturn(mock(CookieProvider.class)).when(session).getProvider(CookieProvider.class);
        doReturn(mock(LoginProtocol.class)).when(session).getProvider(eq(LoginProtocol.class), nullable(String.class));
    }

    @Test
    void emailScreenPreparesPasskeysForAnUnidentifiedUser() {
        stubEmailForm();
        given(context.getUser()).willReturn(null);
        given(context.getAuthenticatorConfig()).willReturn(null);
        given(passkeys.isPasskeysEnabled()).willReturn(true);

        authenticator.authenticate(context);

        verify(passkeys).fillContextForm(context);
        verify(context).challenge(any());
        verify(passkeys, never()).action(any());
    }

    @Test
    void disabledPasskeysLeaveTheEmailScreenUnchanged() {
        stubEmailForm();
        given(context.getUser()).willReturn(null);
        given(context.getAuthenticatorConfig()).willReturn(null);

        authenticator.authenticate(context);

        verify(passkeys, never()).fillContextForm(any());
        verify(context).challenge(any());
    }

    @Test
    void identifiedUserWithoutPasskeysDoesNotGetIncompleteWebAuthnData() {
        stubEmailForm();
        UserModel user = mock(UserModel.class, Answers.RETURNS_DEEP_STUBS);
        given(context.getUser()).willReturn(user);
        given(context.getAuthenticatorConfig()).willReturn(null);
        given(passkeys.isPasskeysEnabled()).willReturn(true);
        given(user.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_PASSWORDLESS))
            .willReturn(false);

        authenticator.authenticate(context);

        verify(passkeys, never()).fillContextForm(any());
        verify(context).challenge(any());
    }

    @Test
    void existingSsoIsNotReplacedWithAPasskeyChallenge() {
        given(context.getUser()).willReturn(mock(UserModel.class));
        given(context.getAuthenticationSession().getAuthNote(org.keycloak.services.managers.AuthenticationManager.SSO_AUTH)).willReturn("true");

        authenticator.authenticate(context);

        verify(context).success();
        verifyNoInteractions(passkeys);
    }

    @ParameterizedTest
    @ValueSource(strings = {WebAuthnConstants.AUTHENTICATOR_DATA, WebAuthnConstants.ERROR})
    void passkeySubmissionWithoutEmailUsesKeycloakVerification(String parameter) {
        MultivaluedMap<String, String> data = new MultivaluedHashMap<>();
        data.add(parameter, "assertion-or-error");
        given(context.getHttpRequest().getDecodedFormParameters()).willReturn(data);
        given(passkeys.isPasskeysEnabled()).willReturn(true);

        authenticator.action(context);

        verify(passkeys).action(context);
        // Never replace the saved challenge before verifying the received assertion.
        verify(passkeys, never()).fillContextForm(any());
        verify(context, never()).attempted();
        verify(context, never()).success();
        verify(context, never()).getSession();
    }

    @Test
    void cancelStillCancelsInsteadOfTryingWebAuthn() {
        MultivaluedMap<String, String> data = new MultivaluedHashMap<>();
        data.add("cancel", "true");
        data.add(WebAuthnConstants.AUTHENTICATOR_DATA, "assertion");
        given(context.getHttpRequest().getDecodedFormParameters()).willReturn(data);

        authenticator.action(context);

        verify(context).cancelLogin();
        verifyNoInteractions(passkeys);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void ordinaryEmailStillUsesDiscoveryAndPasswordFallback(boolean enabled) {
        stubReauthentication();
        KeycloakSession session = context.getSession();
        HomeIdpDiscoverer discoverer = mock(HomeIdpDiscoverer.class);
        doReturn(discoverer).when(session).getProvider(eq(HomeIdpDiscoverer.class), nullable(String.class));
        given(discoverer.discoverForUser(context, "user@example.com")).willReturn(List.of());
        given(passkeys.isPasskeysEnabled()).willReturn(enabled);
        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.putSingle("username", " user@example.com ");
        given(context.getHttpRequest().getDecodedFormParameters()).willReturn(form);

        authenticator.action(context);

        verify(discoverer).discoverForUser(context, "user@example.com");
        verify(context).attempted();
        verify(context.getAuthenticationSession()).setAuthNote(
            HomeIdpDiscoveryAuthenticator.ATTEMPTED_USERNAME, "user@example.com");
        verify(context.getAuthenticationSession()).setClientNote("login_hint", "user@example.com");
        verify(passkeys, never()).action(any());
        verify(passkeys, never()).fillContextForm(any());
        verify(context, never()).success();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "saved-password", " "})
    void discoveryOnlyHandsOffANonemptyPasswordWithinTheRequest(String password) {
        stubReauthentication();
        KeycloakSession session = context.getSession();
        HomeIdpDiscoverer discoverer = mock(HomeIdpDiscoverer.class);
        doReturn(discoverer).when(session).getProvider(eq(HomeIdpDiscoverer.class), nullable(String.class));
        given(discoverer.discoverForUser(context, "user@example.com")).willReturn(List.of());
        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.putSingle("username", " user@example.com ");
        form.putSingle("password", password);
        given(context.getHttpRequest().getDecodedFormParameters()).willReturn(form);

        authenticator.action(context);

        verify(context).attempted();
        verify(context, never()).success(anyString());
        if (password.isEmpty()) {
            verify(session, never()).setAttribute(eq(AutofillUsernamePasswordForm.DISCOVERED_USERNAME), any());
        } else {
            verify(session).setAttribute(AutofillUsernamePasswordForm.DISCOVERED_USERNAME, "user@example.com");
        }
        verify(context.getAuthenticationSession(), never()).setAuthNote(anyString(), eq(password));
    }

    @Test
    void emptyEmailRedisplaysTheEmailFormWithAFreshPasskeyChallenge() {
        stubReauthentication();
        given(context.getHttpRequest().getDecodedFormParameters())
            .willReturn(new MultivaluedHashMap<>());
        given(context.getUser()).willReturn(null);
        given(passkeys.isPasskeysEnabled()).willReturn(true);

        authenticator.action(context);

        verify(passkeys).fillContextForm(context);
        verify(passkeys, never()).action(any());
        verify(context).failureChallenge(any(), any());
    }
}
