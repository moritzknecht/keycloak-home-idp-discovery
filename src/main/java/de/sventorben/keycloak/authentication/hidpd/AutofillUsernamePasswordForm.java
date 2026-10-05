package de.sventorben.keycloak.authentication.hidpd;

import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AuthenticationManager;

import static org.keycloak.services.validation.Validation.FIELD_PASSWORD;

/** Validates a password submitted to discovery without an extra browser round trip. */
final class AutofillUsernamePasswordForm extends UsernamePasswordForm {

    // KeycloakSession attributes live only for the current HTTP request, not in the auth session.
    static final String DISCOVERED_USERNAME = AutofillUsernamePasswordForm.class.getName() + ".username";

    private final KeycloakSession session;

    AutofillUsernamePasswordForm(KeycloakSession session) {
        super(session);
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String username = session.getAttribute(DISCOVERED_USERNAME, String.class);
        session.removeAttribute(DISCOVERED_USERNAME);
        // Leave pre-identified users and password-reset transitions to Keycloak's normal setup.
        if (username != null && context.getUser() == null && !"true".equals(
                context.getAuthenticationSession().getAuthNote("RESET_CREDENTIAL_USER_CHOSEN"))) {
            MultivaluedMap<String, String> data = context.getHttpRequest().getDecodedFormParameters();
            String submittedUsername = data.getFirst(AuthenticationManager.FORM_USERNAME);
            String password = data.getFirst(FIELD_PASSWORD);
            if (submittedUsername != null && username.equals(submittedUsername.trim())
                    && password != null && !password.isEmpty()) {
                context.getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
                // Use native validation, including disabled users, brute-force protection and errors.
                // Only this execution succeeds; later required executions (e.g. OTP) still run.
                super.action(context);
                return;
            }
        }
        super.authenticate(context);
    }
}
