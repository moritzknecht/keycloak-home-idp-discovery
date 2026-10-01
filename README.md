# Keycloak: Home IdP Discovery

This is a simple Keycloak authenticator to redirect users to their home identity provider during login.

![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/sventorben/keycloak-home-idp-discovery?sort=semver)
![Keycloak Dependency Version](https://img.shields.io/badge/Keycloak-26.7.2-blue)
![GitHub Release Date](https://img.shields.io/github/release-date-pre/sventorben/keycloak-home-idp-discovery)
![Github Last Commit](https://img.shields.io/github/last-commit/sventorben/keycloak-home-idp-discovery)

![CI build](https://github.com/sventorben/keycloak-home-idp-discovery/actions/workflows/buildAndTest.yml/badge.svg)
![open issues](https://img.shields.io/github/issues/sventorben/keycloak-home-idp-discovery)
[![CodeScene Code Health](https://codescene.io/projects/53524/status-badges/code-health)](https://codescene.io/projects/53524)

## What is it good for?

When a federated user wants to login via Keycloak, Keycloak will present a username/password form and a list of configured identity providers to the user. The user needs to choose an identity provider to get redirected.
This authenticator allows to skip the step of selecting an identity provider.

## How does it work?

If this authenticator gets configured as part of a browser based login flow, Keycloak will present a username form (without password form and without list of configured identity providers).
A user can then enter an email address. Keycloak will then choose an identity provider based on the domain part of the provided email address and forward the user to the chosen provider.

## Passkeys on the email-first screen

When **Enable Passkeys** is on in Authentication → Policies → WebAuthn Passwordless
Policy, the email-first screen also supports Keycloak's passkey autofill and explicit
passkey button. A discoverable passwordless credential identifies the user without
entering an email address or a password. Submitting an email still uses the existing
home-IdP discovery and subsequent password flow. The provider ID and execution
configuration remain unchanged.

Use **Conditional** mediation, **Required** discoverable credentials and **Required**
user verification. Enable the `Webauthn Register Passwordless` required action without
making it a default action; users can register a passkey in their account console.
Passkeys need HTTPS (or `http://localhost` for development) and a compatible browser.
A WebAuthn credential registered only as a second factor is not a passwordless passkey.

The built-in Keycloak login theme supplies the passkey form and scripts. Custom themes
must preserve `autocomplete="username webauthn"` when `enableWebAuthnConditionalUI`
is present and include `<@passkeys.conditionalUIData />` from `passkeys.ftl` on their
`login-username.ftl` page. A theme must not overwrite that autocomplete value with
plain `username`. When passkeys are disabled, existing discovery behavior is unchanged.
Login-page bypass and existing SSO still take precedence; autofill is available when
the email screen is actually displayed.

Passkey challenges, user lookup, origin/RP-ID checks and signature verification are
handled by Keycloak's `WebAuthnConditionalUIAuthenticator`, not custom cryptography.

## Documentation

Please refer to the [documentation website](https://sventorben.github.io/keycloak-home-idp-discovery/) for instructions on installation, configuration, features, and general usage.


[![Youtube Video - Interview with Niko Köbler](https://img.youtube.com/vi/4jSBqens2yA/0.jpg)](https://www.youtube.com/watch?v=4jSBqens2yA)
