# KUROKO Script API — GitHub Pages + Cloudflare Worker

This package separates the static dashboard (GitHub Pages) from the API backend (Cloudflare Worker + D1).

## Important
GitHub Pages cannot run Python or keep server-side secrets. The dashboard alone is not a working secure API. Deploy `worker.js` as a Cloudflare Worker and bind a D1 database using `schema.sql`.

## Publish the dashboard on GitHub Pages
1. Put `index.html` at the root of your GitHub repository.
2. Open Settings → Pages.
3. Choose Deploy from a branch, branch `main`, folder `/ (root)`, then Save.
4. Wait for the GitHub Pages URL, commonly `https://USERNAME.github.io/REPOSITORY/`.

## Configure the backend
1. In Cloudflare, create a D1 database (e.g. `script-api-db`).
2. Open its SQL console and run all statements in `schema.sql`.
3. Create a Worker and paste `worker.js`.
4. Bind the D1 database to the Worker under the variable name `DB`.
5. Set Worker variables/secrets:
   - `ADMIN_USERNAME`: your private admin username.
   - `ADMIN_PASSWORD_SHA256`: SHA-256 hex digest of a long unique admin password.
   - `TOKEN_SECRET`: a long random secret (at least 32 random bytes).
   - `SCRIPT_SOURCE`: your script text (or change the Worker to load it from a private storage service).
6. Deploy the Worker and copy its `workers.dev` URL.
7. Open your GitHub Pages site, paste the Worker URL in “رابط API”, and save it.

### Creating password hash
Use a trusted local SHA-256 utility or a local Python shell:
```python
import hashlib, getpass
print(hashlib.sha256(getpass.getpass("Admin password: ").encode()).hexdigest())
```
Never commit the password, hash, or token secret to GitHub. Set them only in Cloudflare Worker settings.

## Endpoints
- `POST /api/admin/login` JSON `{ "username": "...", "password": "..." }`
- `POST /api/admin/keys` (admin bearer token) JSON `{ "label":"tester", "kind":"temporary", "hours":24 }`
- `POST /api/admin/dashboard` (admin bearer token) JSON `{}`
- `POST /api/admin/keys/{id}/revoke` (admin bearer token)
- `POST /api/activate` JSON `{ "key":"SK-...", "client_id":"optional" }`
- `POST /api/script` JSON `{ "key":"SK-...", "client_id":"optional" }`

## Notes and limits
- The UI is a static dashboard. It does not become functional until the Worker is deployed and configured.
- The worker's sample password hash uses SHA-256 for simplicity, not a password KDF. For serious production use, use a managed authentication provider or replace with PBKDF2/Argon2 verification and rate limiting.
- Add rate limiting and abuse monitoring before public use.
- A client ID is supplied by the client and can be spoofed; it is not proof of Roblox identity.
- Any script delivered to a client can potentially be copied. Keys control access, not copying after delivery.
- Use only scripts you own or are authorized to distribute. Delta compatibility is not guaranteed.
