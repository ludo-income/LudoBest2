# Ludo Best 2 — Brevo Gmail OTP + Admin Foundation

This version removes the Download App button/section and provides:
- Sign Up with name + Bangladesh mobile + Gmail
- Real OTP delivery to the user's Gmail address through Brevo Transactional Email API
- Gmail OTP verification before account activation
- Login with Gmail + a fresh Gmail OTP
- OTP expiry, hashed OTP storage, attempt limits and resend rate limiting
- PostgreSQL-ready persistent database for Render
- JWT sessions
- Admin login and mobile-friendly admin dashboard
- User list and active/blocked control
- Payment-method management foundation (name, account number, image URL, instructions, enable/disable)

## Render setup
1. Create a Render PostgreSQL database.
2. Create the Web Service from this ZIP/repository.
3. Add the Environment Variables from `.env.example`.
4. In Brevo, create/verify the sender email and create a transactional API key.
5. Generate an admin bcrypt hash and set it as `ADMIN_PASSWORD_HASH`.
6. Deploy. `/` is the user site and `/admin` is the admin panel.

The project intentionally does not use `better-sqlite3`, so Render's Node 26 build does not need a native SQLite compilation step.
