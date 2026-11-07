# Games Night’s Song Competition (Vercel version)

Accounts, rounds, duos, anonymous scoring and an admin panel, built for Vercel:
- **Database:** Neon Postgres (from the Vercel Marketplace)
- **mp3 storage:** Vercel Blob (browser uploads straight to Blob, so file size isn’t limited by Vercel’s 4.5 MB request cap)
- **Server:** one Express function in `api/index.js`, front end in `public/index.html`

## Deploy
1. Put this folder in a GitHub repo and import it into Vercel as a new project (Framework: Other).
2. In the project’s **Storage** tab:
   - Add **Neon (Postgres)**. This creates `DATABASE_URL`.
   - Add a **Blob** store. This creates `BLOB_READ_WRITE_TOKEN`. Create it as a public store.
3. In **Settings → Environment Variables** add:
   - `SECRET` : any long random string (shuffles song letters A, B, C…)
   - `ADMIN_USER`, `ADMIN_PASS`, `ADMIN_NAME` : your admin login (only used while the database is empty)
4. Deploy, open the site, log in as the admin, and use **Admin panel → Add a player** to create the other accounts. The panel shows each password once so you can send it. After the first login you can delete `ADMIN_PASS` from the env vars.

Tables are created automatically on the first request.

## Local testing
`npm i -g vercel`, then `vercel link`, `vercel env pull`, `vercel dev`.

## Privacy notes
- Passwords are bcrypt-hashed, logins are rate-limited, sessions are HttpOnly cookies.
- The API only gives out an mp3 link after checking the round phase (your own song any time, others only while voting is open, never your partner’s, or after results).
- Blob files are stored with a long random suffix in the name, so links can’t be guessed, but anyone who is handed a link can open it. Don’t share song links outside the group.
- Voter IDs sit in the database so people can update scores. The app and API never show them.
