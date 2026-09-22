# Ludo Best 2 — Render/Brevo fixed build

This archive is intentionally **flat**: `package.json`, `server/`, and `public/` are at the repository root.

## Render
- Runtime: Node
- Build Command: `npm install`
- Start Command: `node ./server/server.js`
- Node: 20.x (via package.json/.nvmrc)

## Required environment variables
- `DATABASE_URL`
- `BREVO_API_KEY`
- `BREVO_SENDER_EMAIL`
- `BREVO_SENDER_NAME` (optional)
- `JWT_SECRET`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD_HASH`
- `OTP_EXPIRES_MINUTES` (optional, default 10)

## Important
Do not upload the outer ZIP directory name as an extra project root. Put the **contents of this ZIP directly in the GitHub repository root**. The deployed repository must contain:

```
package.json
server/server.js
public/index.html
public/admin.html
render.yaml
```

Health check: `/health`
Admin panel: `/admin`
