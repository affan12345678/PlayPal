# PlayPal

Modern React + Vite + Tailwind frontend for a community sports and fitness platform.

## Run locally

```powershell
npm install
npm run dev
```

## Backend API

The FastAPI backend owns the sports, venues, players, sessions, and session
membership data. It seeds a local SQLite database on first run.

```powershell
py -m pip install -r backend/requirements.txt
py -m uvicorn backend.app:app --reload
```

API documentation is available at `http://localhost:8000/docs`. The frontend
base URL is already configured in `.env.example`.

`POST /sessions/{id}/join` joins a match or activity and
`DELETE /sessions/{id}/join` leaves it. The API rejects a leave request made
within two hours of the session start. Both endpoints require the JWT bearer
token returned by signup or login.

## Main routes

- `/`
- `/discover`
- `/group-sports`
- `/individual-sports`
- `/fitness-buddies`
- `/sports/cricket`
- `/sports/football`
- `/sports/basketball`
- `/sports/pickleball`
- `/sports/badminton`
- `/players`
- `/players/:id`
- `/matches`
- `/matches/:id`
- `/create-match`
- `/tournaments`
- `/tournaments/:id`
- `/leaderboard`
- `/fitness`
- `/challenges`
- `/dashboard`
- `/signup`
- `/login`
- `/verify-otp`
- `/profile/setup`

## Demo authentication

Mobile authentication uses a local demo OTP. No SMS is sent. Use `123456` during verification.

Google/Gmail is represented as an integration-ready demo path; connect Supabase Auth or another OAuth provider for production credentials.

## Notes

State changes for match joins, tournament registration, connections and notifications are held in frontend state, with selected demo state persisted through `localStorage`.

The backend is the source of truth for authenticated users, sessions,
tournament registrations, connections, and notifications. Signup and login use
username, display name, and password; passwords are hashed and the API returns
a JWT bearer token. The frontend stores only that access token locally and
does not persist match, tournament, connection, notification, or profile state
in `localStorage`.
