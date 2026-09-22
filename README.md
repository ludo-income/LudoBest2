# Ludo Best 2 — Gmail OTP Authentication

This version removes the Download App button/section and adds:
- Real Sign Up with name + Bangladesh mobile + Gmail + password
- Real Gmail OTP verification before account activation
- Login with Gmail + password + a fresh Gmail OTP
- OTP expiry, hashed OTP storage, attempt limits and resend rate limiting
- SQLite user database
- JWT login session
- Render deployment configuration

## Run locally
1. Install Node.js 18+.
2. Copy `.env.example` to `.env` and fill in `JWT_SECRET`, `GMAIL_USER`, and `GMAIL_APP_PASSWORD`.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000`.

## Gmail OTP setup
Use a Gmail account with 2-Step Verification enabled and create a Google App Password. Put the Gmail address in `GMAIL_USER` and the 16-character App Password in `GMAIL_APP_PASSWORD`. Never put these secrets in frontend code.

## Render
Create a Node Web Service from this project. Render uses `render.yaml` for the build/start commands. Add the secret environment variables in Render. The SQLite database is stored under `data/`; for production with persistent user data, attach a persistent disk or move the database to a managed database before going live.
