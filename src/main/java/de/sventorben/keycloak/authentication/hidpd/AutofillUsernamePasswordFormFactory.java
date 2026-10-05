package de.sventorben.keycloak.authentication.hidpd;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.KeycloakSession;

/** Extends the native execution so existing browser flows need no configuration changes. */
public final class AutofillUsernamePasswordFormFactory extends UsernamePasswordFormFactory {

    @Override
    public Authenticator create(KeycloakSession session) {
        return new AutofillUsernamePasswordForm(session);
    }

    @Override
    public int order() {
        // Select this factory over Keycloak's default factory for the same provider ID.
        return 1;
    }
}
