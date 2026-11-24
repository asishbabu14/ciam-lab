# Token and sign-in troubleshooting

Personal lab. Synthetic users. The failures below are produced on purpose by the test suite so you can see the check that rejects the token, and the change that makes the same call succeed.

Run a single case from the repo root after `python -m pip install -e ".[dev]"`:

```bash
pytest tests/test_troubleshooting.py -q
```

`make demo` walks the happy paths and then performs the ID token versus access token failure, including the retry that fixes it.

Validators share one implementation: `ciam_lab.tokens.TokenValidator`. The orders API, the OIDC callback, and the unit tests all call it. Signature checks go through Authlib and the provider JWKS.

## Redirect URI mismatch

**What you see.** HTTP 400 `invalid_request` with "redirect_uri is not registered for this client", or `invalid_grant` with "redirect_uri does not match the authorization request" at the token endpoint. The provider does not redirect to an unregistered URI.

**Why.** The redirect URI is part of the client's registration and part of the authorization code. A difference of host, port, path, or slash is a different URI.

**How the lab reproduces it.**

- `tests/test_oidc.py::test_redirect_uri_mismatch_on_authorize` calls `/authorize` with `redirect_uri=http://evil.example/callback`.
- `tests/test_oidc.py::test_redirect_uri_mismatch_on_token` finishes a real login up to the code, then posts the token request with a different redirect URI.

**Fix.** Register the exact callback the storefront uses. Locally that is `http://127.0.0.1:8000/callback`. In Auth0, put that same URL in Allowed Callback URLs. The token request must repeat the redirect URI that was used at `/authorize`.

## Audience mismatch

**What you see.** HTTP 401 `audience_mismatch`. The check detail shows the `aud` value that arrived and the audience the component expected.

**Why.** An ID token's audience is the client. An access token's audience is the API (`https://api.fieldnote.lab` in this lab, or `AUTH0_AUDIENCE`). Sending either token to the wrong component fails this check.

**How the lab reproduces it.** `tests/test_tokens.py::test_audience_mismatch` validates a genuine access token while expecting `https://wrong.example`.

**Fix.** Request the API audience when you want to call the API. Validate ID tokens with the client id, and access tokens with the API identifier. Do not reuse one audience for both.

## Clock skew

**What you see.** HTTP 401 `clock_skew`. The message says `iat` is too far in the future, or `nbf` is still in the future, beyond the leeway.

**Why.** The lab allows `TOKEN_LEEWAY_SECONDS` (default 10) so a second or two of drift between machines still works. A token that claims to be issued further ahead than that is rejected. A token that expired only a few seconds ago is still accepted, which is the other side of the same window.

**How the lab reproduces it.**

- `tests/test_tokens.py::test_clock_skew_within_leeway` uses `exp` five seconds in the past with a 10 second leeway. Validation succeeds.
- `tests/test_tokens.py::test_clock_skew_beyond_leeway` uses `iat` sixty seconds in the future. Validation fails with `clock_skew`.

**Fix.** Sync the host clock. Do not paper over a large skew by raising the leeway in a real deployment. In the lab you can set `TOKEN_LEEWAY_SECONDS` if you are demonstrating the window.

## Expired token

**What you see.** HTTP 401 `expired`. The message includes `exp`, the validator's idea of now, and the leeway.

**Why.** `exp` is at or before `now - leeway`. Signing was fine. The token is simply too old.

**How the lab reproduces it.** `tests/test_tokens.py::test_expired_token` mints an access token whose `exp` is 30 seconds before the validator clock, with the default 10 second leeway.

**Fix.** Sign in again. The local providers issue tokens that live for five minutes. Refresh is out of scope for this lab.

## Nonce mismatch

**What you see.** The callback returns HTTP 400 `nonce_mismatch`. No session is stored.

**Why.** The storefront put a nonce in the authorize request and kept a copy. The ID token came back with a different nonce, so this response is not the one that belongs to this browser's login.

**How the lab reproduces it.** `tests/test_troubleshooting.py::test_nonce_mismatch` starts a real PKCE login, replaces the stored nonce, and lets the callback compare it with the ID token.

**Fix.** Start a new login. Do not edit the nonce, and do not reuse an ID token from an older attempt.

## State mismatch

**What you see.** The callback returns HTTP 400 `state_mismatch` before the code is exchanged.

**Why.** `state` ties the redirect to the browser that started the request. If it does not match the stored value, the client must stop. That is the CSRF check for the redirect.

**How the lab reproduces it.** `tests/test_troubleshooting.py::test_state_mismatch` replaces the stored state after the authorize redirect has already been built. The provider echoes the original state, and the storefront rejects it.

**Fix.** Start a new login. Keep the state in the client session and compare it to the query parameter before calling the token endpoint.

## ID token used as an access token

**What you see.** HTTP 401 `id_token_used_as_access_token`. The body explains that an ID token tells the client who signed in, and an access token is what the API accepts. The same response includes a `fix` line.

**Why.** Both values are JWTs, so it is easy to attach the wrong one to `Authorization: Bearer`. The lab marks local tokens with `token_use` (`id` or `access`) and also gives them different audiences. The API checks `token_use` first, so this case is not reported as a generic audience error.

**How the lab reproduces it.**

- `make demo` section 5 calls `GET /api/orders` with the ID token, prints the error and the fix, then retries with the access token and gets HTTP 200.
- `tests/test_troubleshooting.py::test_id_token_is_rejected_by_the_api` is the same pair of calls.
- `tests/test_troubleshooting.py::test_userinfo_rejects_an_id_token` sends the ID token to the provider userinfo endpoint.
- `tests/test_tokens.py::test_id_token_rejected_as_access_token` covers the validator directly.

**Fix.** Send the access token to the API and to userinfo. Keep the ID token in the client and validate it when the login callback arrives.

## Passkey registration failure

**What you see.** HTTP 400 `origin_mismatch` or `ceremony_mismatch`.

**Why.** Registration (`navigator.credentials.create`, client data type `webauthn.create`) and authentication (`navigator.credentials.get`, `webauthn.get`) are different ceremonies. The provider also requires the origin to be its own origin. An attestation built for another origin is rejected even when the signature is otherwise well formed. Registration requires a signed-in provider session. Authentication does not.

**How the lab reproduces it.**

- `tests/test_troubleshooting.py::test_passkey_registration_rejects_the_wrong_origin` registers with origin `http://evil.example`.
- `tests/test_troubleshooting.py::test_passkey_ceremony_mixup` posts an authentication assertion to the registration endpoint, and a registration attestation to the authentication endpoint.

**Fix.** Call the register endpoints only from a create ceremony whose origin is the provider origin (`http://127.0.0.1:9000` by default). Sign in with the password form first if the provider session is missing. Use the soft authenticator in tests, or the button on the provider security page in a browser.

## Passkey authentication failure

**What you see.** HTTP 400 `unknown_credential`, `no_passkey`, or `sign_count`.

**Why.** Authentication only succeeds for a credential id the provider stored at registration. A user with no passkey yet is told to register first. After a successful assertion the provider stores the new sign count and rejects a later assertion that does not increase it, which is how a replay of the same counter is caught.

**How the lab reproduces it.**

- `tests/test_troubleshooting.py::test_passkey_authentication_rejects_an_unknown_credential` replaces the credential id on an otherwise real assertion.
- `tests/test_webauthn.py::test_sign_count_must_increase` rewinds the soft authenticator counter and signs in again.
- Asking `/webauthn/authenticate/options` for a user who never registered returns `no_passkey`.

**Fix.** Register the passkey, then authenticate with that same credential. Do not reuse an assertion. If sign count fails, the credential may have been cloned or the counter was rewound. Register a new passkey for the lab user and try the sign-in again.

## Related checks

These are covered by the same validator and are useful while you are in the file:

| Check | Test |
| --- | --- |
| Bad signature | `tests/test_tokens.py::test_bad_signature` |
| Wrong issuer | `tests/test_tokens.py::test_issuer_mismatch` |
| Missing scope on a real access token | `tests/test_api.py::test_missing_scope_is_forbidden` |
| User denied consent | `tests/test_api.py::test_denied_consent_returns_access_denied` |
