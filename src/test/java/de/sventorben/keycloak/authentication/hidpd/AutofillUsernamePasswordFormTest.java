package de.sventorben.keycloak.authentication.hidpd;

import jakarta.ws.rs.core.MultivaluedHashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AutofillUsernamePasswordFormTest {

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    AuthenticationFlowContext context;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    KeycloakSession session;

    private MockedStatic<Profile> profile;
    private AutofillUsernamePasswordForm authenticator;
    private MultivaluedHashMap<String, String> data;

    @BeforeEach
    void setUp() {
        profile = mockStatic(Profile.class);
        lenient().when(context.getUser()).thenReturn(null);
        authenticator = spy(new AutofillUsernamePasswordForm(session));
        data = new MultivaluedHashMap<>();
        data.putSingle("username", " user@example.com ");
        data.putSingle("password", "saved-password");
    }

    @AfterEach
    void tearDown() {
        profile.close();
    }

    private void stubHandoff() {
        when(session.getAttribute(AutofillUsernamePasswordForm.DISCOVERED_USERNAME, String.class))
            .thenReturn("user@example.com");
        when(context.getHttpRequest().getDecodedFormParameters()).thenReturn(data);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void handsTheCurrentPostToNativeValidationOnlyOnce(boolean valid) {
        stubHandoff();
        doReturn(valid).when(authenticator).validateUserAndPassword(context, data);

        authenticator.authenticate(context);

        verify(authenticator).validateUserAndPassword(context, data);
        verify(session).removeAttribute(AutofillUsernamePasswordForm.DISCOVERED_USERNAME);
        verify(context.getAuthenticationSession()).removeAuthNote(
            AutofillUsernamePasswordForm.USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
        if (valid) {
            verify(context).success("password");
        } else {
            verify(context, never()).success(anyString());
        }
        verify(context, never()).challenge(any());
        verify(session, never()).setAttribute(anyString(), any());
    }

    @Test
    void aPasswordPostWithoutDiscoveryStillShowsTheNormalLoginForm() {
        when(context.getSession()).thenReturn(session);

        authenticator.authenticate(context);

        verify(context).challenge(any());
        verify(context, never()).getHttpRequest();
        verify(authenticator, never()).validateUserAndPassword(any(), any());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void anAbsentPasswordKeepsThePasswordStep(String password) {
        stubHandoff();
        when(context.getSession()).thenReturn(session);
        data.putSingle("password", password);

        authenticator.authenticate(context);

        verify(context).challenge(any());
        verify(authenticator, never()).validateUserAndPassword(any(), any());
    }

    @Test
    void aDifferentUsernameCannotUseTheHandoff() {
        stubHandoff();
        when(context.getSession()).thenReturn(session);
        data.putSingle("username", "someone-else@example.com");

        authenticator.authenticate(context);

        verify(context).challenge(any());
        verify(authenticator, never()).validateUserAndPassword(any(), any());
    }

    @Test
    void preIdentifiedUsersKeepTheNativeSetup() {
        when(session.getAttribute(AutofillUsernamePasswordForm.DISCOVERED_USERNAME, String.class))
            .thenReturn("user@example.com");
        when(context.getSession()).thenReturn(session);
        when(context.getUser()).thenReturn(mock(UserModel.class));

        authenticator.authenticate(context);

        verify(context).challenge(any());
        verify(authenticator, never()).validateUserAndPassword(any(), any());
    }

    @Test
    void resetPasswordTransitionsKeepTheNativeSetup() {
        when(session.getAttribute(AutofillUsernamePasswordForm.DISCOVERED_USERNAME, String.class))
            .thenReturn("user@example.com");
        when(context.getSession()).thenReturn(session);
        when(context.getAuthenticationSession().getAuthNote("RESET_CREDENTIAL_USER_CHOSEN"))
            .thenReturn("true");

        authenticator.authenticate(context);

        verify(context).clearUser();
        verify(context).challenge(any());
        verify(authenticator, never()).validateUserAndPassword(any(), any());
    }

    @Test
    void factoryExtendsTheExistingExecutionWithoutAFlowMigration() {
        AutofillUsernamePasswordFormFactory factory = new AutofillUsernamePasswordFormFactory();
        assertEquals(new UsernamePasswordFormFactory().getId(), factory.getId());
        assertTrue(factory.order() > new UsernamePasswordFormFactory().order());
        assertInstanceOf(AutofillUsernamePasswordForm.class, factory.create(session));
    }
}
