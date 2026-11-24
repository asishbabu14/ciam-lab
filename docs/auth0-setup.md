# Point the lab at Auth0

Do this yourself in an Auth0 free-plan tenant. The lab never ships a tenant, a client secret, or a token. Put the four values in the environment, not in git.

Local mode does not need any of this. `make demo` always stays on `MOCK:local-idp` and `MOCK:enterprise-idp`.

## 1. Create the tenant

1. Create an Auth0 account and a tenant.
2. Pick any region. The lab only needs the tenant domain, for example `your-tenant.us.auth0.com`.

## 2. Create the application

1. In Applications, create an application of type Regular Web Application.
2. Name it something you will recognize, such as `ciam-lab`.
3. Open the application settings and set:
   - Allowed Callback URLs: `http://127.0.0.1:8000/callback`
   - Allowed Logout URLs: `http://127.0.0.1:8000/`
   - Allowed Web Origins: `http://127.0.0.1:8000`
4. Save.
5. Copy the Domain, Client ID, and Client Secret into your shell or a local `.env` that is gitignored.

The callback URL has to match exactly. A missing trailing path, an extra slash, or `localhost` instead of `127.0.0.1` is the usual redirect URI failure. See [troubleshooting.md](troubleshooting.md).

## 3. Create the API audience

1. In Applications, then APIs, create an API.
2. Set the identifier to `https://api.fieldnote.lab`. This string is the access token audience. It does not need to be a host you control.
3. Add permissions `orders:read` and `orders:write`.
4. Turn on RBAC and "Add Permissions in the Access Token" if you want those permissions copied onto the token.
5. Save.

The lab reads the space-separated `scope` claim. When you sign in, the storefront requests `openid profile email orders:read orders:write`. After login, open `/session` or the account page and confirm the access token `scope` contains `orders:read`. If Auth0 omitted it, authorize the application for those permissions and sign in again.

Auth0 returns a JWT access token when the authorize request includes this audience. Without an audience the access token is often opaque, and the lab rejects it because it cannot check a signature.

## 4. Run the storefront

```bash
export IDP_MODE=auth0
export AUTH0_DOMAIN=your-tenant.us.auth0.com
export AUTH0_CLIENT_ID=paste-client-id
export AUTH0_CLIENT_SECRET=paste-client-secret
export AUTH0_AUDIENCE=https://api.fieldnote.lab
python -m ciam_lab.serve
```

Open http://127.0.0.1:8000 and use Sign in. Auth0 hosts the login page. The lab then validates:

- ID token: issuer `https://your-tenant.us.auth0.com/` (Auth0 includes the trailing slash; the lab copies `issuer` from discovery), audience equal to the client id, expiry, signature via the tenant JWKS, and nonce.
- Access token: same issuer, audience equal to `AUTH0_AUDIENCE`, expiry, and signature.

If a variable is missing, startup fails and names the variable. The message points back at this file.

## 5. Optional enterprise connection

1. In Authentication, then Enterprise, create the connection your tenant supports and enable it for the `ciam-lab` application.
2. Copy the connection identifier Auth0 shows (the value it expects in the `connection` parameter).
3. Export it:

```bash
export AUTH0_ENTERPRISE_CONNECTION=that-connection-name
```

The "Sign in with your organization" button adds `connection` to the authorize request. If the variable is unset, that button explains what to set instead of sending a broken request.

The fully offline federation tour is local mode, where `MOCK:local-idp` brokers `MOCK:enterprise-idp`. Use that when you want the lab to run without Auth0.

## 6. What stays local

Passkey registration in this lab is implemented on `MOCK:local-idp` and exercised by the soft authenticator. Auth0 can offer passkeys from the Auth0 dashboard, but this repository does not call that API. Use `make demo` or `IDP_MODE=local` for the passkey tour.

## 7. Keep secrets out of git

`.gitignore` ignores `.env`. `.env.example` only has placeholders. Do not paste the client secret into a commit, a test, or a screenshot you plan to publish.

Rotate the client secret in the Auth0 dashboard if it is ever copied into a file that was committed.
