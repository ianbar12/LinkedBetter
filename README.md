# ProfileSignal

ProfileSignal runs as a small Node.js web server. Open it through the server URL; do not double-click `index.html` or open it as `file://`.

## Start the server and open the app

The app listens on port **8787** by default. From Terminal:

```sh
cd /Users/ianbarrow/Documents/Codex/2026-09-22/show-x20/outputs
node server.mjs
```

Leave that terminal window running, then open **http://localhost:8787** in your browser. The page's **OAuth configuration check** and `/api/status` endpoint confirm that the backend is reachable and show whether local setup values are present. `Ctrl+C` stops the server; run `node server.mjs` again after changing `.env`.

This local HTTP URL is for checking that the app is served correctly. LinkedIn OAuth itself must use the HTTPS ngrok URL below. Keep the browser on that same ngrok host through authorization so the OAuth session cookie and callback reach the same server.

## HTTPS test with ngrok

1. Install the ngrok agent and configure your ngrok authtoken using the official [ngrok setup instructions](https://ngrok.com/use-cases/share-localhost). Do not put the ngrok authtoken in this app's `.env` or send it in chat.
2. Start the app as above.
3. In a second Terminal window, start a tunnel:

   ```sh
   ngrok http 8787
   ```

4. Copy the HTTPS **Forwarding** URL printed by ngrok. For example, if ngrok prints `https://example.ngrok.app`, the callback URL to register in LinkedIn is exactly:

   ```text
   https://example.ngrok.app/auth/linkedin/callback
   ```

   The host varies per ngrok tunnel unless you use a reserved ngrok domain. Replace the placeholder host in `.env` with your actual URL; the app requires HTTPS. Register that exact full callback URL under the LinkedIn app's Authorized Redirect URLs. Open the app using `https://example.ngrok.app`, not `http://localhost:8787`, to begin OAuth.

5. Enable **Sign In with LinkedIn using OpenID Connect** for the LinkedIn app. This is required for the `openid` and `profile` scopes the app requests. LinkedIn's Developer Portal settings are account-specific; this workspace cannot verify whether the product has been enabled for your app.
6. Set the real `LINKEDIN_CLIENT_ID` and `LINKEDIN_CLIENT_SECRET` in the private `.env` file. Never paste the secret into frontend code or chat. Keep `TOKEN_ENCRYPTION_KEY` as the generated 64-character hex key already in `.env`.
7. Stop and restart the app (`Ctrl+C`, then `node server.mjs`). Leave ngrok running. Visit `/api/status` on your ngrok HTTPS URL and confirm the callback host matches exactly, then click **Connect LinkedIn**.

The callback is always:

```text
https://<the-exact-ngrok-host>/auth/linkedin/callback
```

The path, protocol, host, port (if any), and trailing slash must match the value of `LINKEDIN_REDIRECT_URI` exactly. The server refuses non-HTTPS callback values. If you restart ngrok and it assigns a different host, update both LinkedIn Developer Portal and `.env`, then restart the server.

## Configuration and troubleshooting

A private `.env` with placeholder LinkedIn values has been created from `.env.example`. Replace placeholders locally. `.gitignore` excludes `.env` and the encrypted token data directory. The server loads `.env` automatically, so the command is exactly `node server.mjs`; shell environment values take precedence over `.env` values.

`GET /api/status` reports whether LinkedIn credentials and the token encryption key are configured (never their contents), the callback URL and HTTPS status, official authorization/token endpoints, and requested scopes. It cannot inspect LinkedIn's Developer Portal or confirm your client ID/secret are valid. The OAuth consent result and server logs provide the account-specific answer. LinkedIn errors are shown with stage, category, HTTP status, provider error code, and provider description; server logs redact token/secret fields. A plain `Failed to fetch` on a `file://` page means the request never reached this server or LinkedIn.

The app starts without real LinkedIn credentials so you can verify the web server, but `/auth/linkedin` intentionally returns a credentials setup error until real values replace the placeholders. No fake connection is created. The server exchanges the code at LinkedIn's official token endpoint, then validates the access token with an authenticated `GET https://api.linkedin.com/v2/userinfo`; it only reports connected if LinkedIn accepts that request.

## LinkedIn scopes and profile fields

The app requests only `openid profile`; it does not request email or write access. LinkedIn documents these OpenID Connect permissions and requires the OpenID Connect product in the Developer Portal. The standard userinfo endpoint provides an app-scoped member identifier, name, and profile picture when available. The app does not scrape LinkedIn. Headline, About, education, experience, skills, projects, and certifications can be entered manually for analysis when unavailable from the userinfo response.

## Storage and privacy

Access tokens are stored in an AES-256-GCM encrypted JSON file under `data/`; the encryption key stays in `.env`. The browser gets an HttpOnly, SameSite=Lax session cookie and never receives the token. This starter has no separate app password/account system: LinkedIn's OIDC subject is the account key, and sessions are in memory until restart. The user-entered profile text and LinkedIn profile photo URL (if available) are sent to the configured OpenAI Responses API for review; profile text and AI results are not saved.
