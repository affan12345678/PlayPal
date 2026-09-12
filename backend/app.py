"""PlayPal backend.

Only the public sports and venues catalogues are seeded. User-owned data
always uses the authenticated bearer token.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
from queue import Empty, Queue
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "playpal.db"
IST = timezone(timedelta(hours=5, minutes=30))
JWT_SECRET = os.getenv("PLAYPAL_JWT_SECRET", "change-this-playpal-secret-in-production").encode()
JWT_TTL = timedelta(days=7)
bearer = HTTPBearer(auto_error=False)

EVENT_SUBSCRIBERS: dict[int, set[Queue]] = {}
EVENT_SUBSCRIBERS_LOCK = threading.Lock()


def publish_event(target_user_id: int, event: dict[str, Any]) -> None:
    with EVENT_SUBSCRIBERS_LOCK:
        subscribers = list(EVENT_SUBSCRIBERS.get(target_user_id, set()))
    for subscriber in subscribers:
        subscriber.put_nowait(event)


def publish_notification(target_user_id: int, notification_id: int) -> None:
    publish_event(target_user_id, {"type": "notification", "notification_id": notification_id})


def publish_connection_change(*user_ids: int) -> None:
    for target_user_id in set(user_ids):
        publish_event(target_user_id, {"type": "connection_changed"})


async def event_stream(target_user_id: int):
    subscriber: Queue = Queue()
    with EVENT_SUBSCRIBERS_LOCK:
        EVENT_SUBSCRIBERS.setdefault(target_user_id, set()).add(subscriber)

    try:
        yield "event: connected\ndata: {}\n\n"
        while True:
            try:
                event = await asyncio.to_thread(subscriber.get, True, 20)
                yield f"event: playpal\ndata: {json.dumps(event)}\n\n"
            except Empty:
                yield ": keep-alive\n\n"
    finally:
        with EVENT_SUBSCRIBERS_LOCK:
            subscribers = EVENT_SUBSCRIBERS.get(target_user_id)
            if subscribers:
                subscribers.discard(subscriber)
                if not subscribers:
                    EVENT_SUBSCRIBERS.pop(target_user_id, None)


app = FastAPI(title="PlayPal API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://your-site-name.netlify.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

AVAILABILITY_STATUSES = ("Available to Play", "Busy", "In a Match")
MINIMUM_SIGNUP_AGE = 18


@contextmanager
def db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def rows(connection: sqlite3.Connection, query: str, params: tuple = ()):
    return [dict(row) for row in connection.execute(query, params).fetchall()]


def now() -> datetime:
    return datetime.now(IST)


def calculate_age(date_of_birth: date | str | None, today: date | None = None) -> int | None:
    """Calculate a person's completed years using the server's current date."""
    if not date_of_birth:
        return None
    try:
        birth_date = (
            date_of_birth
            if isinstance(date_of_birth, date)
            else date.fromisoformat(str(date_of_birth)[:10])
        )
    except (TypeError, ValueError):
        return None
    current_date = today or now().date()
    age = current_date.year - birth_date.year
    if (current_date.month, current_date.day) < (birth_date.month, birth_date.day):
        age -= 1
    return age if age >= 0 else None


def validate_date_of_birth(value: date | None):
    if value is None:
        return
    current_date = now().date()
    if value > current_date:
        raise HTTPException(422, "Date of birth cannot be in the future")
    if calculate_age(value, current_date) < MINIMUM_SIGNUP_AGE:
        raise HTTPException(422, "You must be at least 18 years old to create a PlayPal account")


def validate_signup_preferences(connection: sqlite3.Connection, preferences: list[str]) -> list[str]:
    normalized = []
    seen = set()
    for preference in preferences:
        value = preference.strip()
        if not value:
            continue
        if value in seen:
            continue
        normalized.append(value)
        seen.add(value)

    allowed_rows = connection.execute("SELECT name FROM sports").fetchall()
    allowed = {row["name"] for row in allowed_rows}
    invalid = [value for value in normalized if value not in allowed]
    if invalid:
        raise HTTPException(422, f"Unsupported sport or activity: {invalid[0]}")
    return normalized


def password_hash(password: str) -> str:
    """Hash passwords with a salted, deliberately expensive KDF."""
    iterations = 310_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def password_matches(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        algorithm, iteration_text, salt_text, digest_text = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_text), int(iteration_text)
        )
        return hmac.compare_digest(digest.hex(), digest_text)
    except (TypeError, ValueError):
        return False


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def make_token(user_id: int) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(
        json.dumps(
            {"sub": str(user_id), "iat": int(now().timestamp()), "exp": int((now() + JWT_TTL).timestamp())},
            separators=(",", ":"),
        ).encode()
    )
    message = f"{header}.{payload}".encode()
    signature = _b64(hmac.new(JWT_SECRET, message, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def token_user_id(token: str) -> int:
    try:
        header, payload, signature = token.split(".")
        expected = _b64(hmac.new(JWT_SECRET, f"{header}.{payload}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        data = json.loads(_unb64(payload))
        if int(data["exp"]) < int(now().timestamp()):
            raise ValueError
        return int(data["sub"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, UnicodeError, binascii.Error):
        raise HTTPException(status_code=401, detail="Invalid or expired access token")


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> dict[str, Any]:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    user_id = token_user_id(credentials.credentials)
    with db() as connection:
        user = connection.execute(
            """SELECT id, username, display_name, email, date_of_birth,
                      availability_status, created_at
               FROM users WHERE id=?""",
            (user_id,),
        ).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
    result = dict(user)
    result["age"] = calculate_age(result.get("date_of_birth"))
    result["status"] = result.get("availability_status") or "Available to Play"
    result["availability"] = result["status"]
    return result

@app.get("/events")
async def events(user: dict[str, Any] = Depends(current_user)):
    return StreamingResponse(
        event_stream(user_id(user)),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )



def optional_user_id(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> int | None:
    if not credentials:
        return None
    return user_id(current_user(credentials))


def user_id(user: dict[str, Any]) -> int:
    return int(user["id"])


class SignupInput(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    display_name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=8, max_length=200)
    email: str | None = Field(default=None, max_length=254)
    date_of_birth: date | None = None
    experience: Literal["Beginner", "Intermediate", "Advanced", "Professional"] = "Beginner"
    gender: Literal["Male", "Female", "Other"] = "Other"
    preferred_sports: list[str] = Field(default_factory=list)


class ProfileUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    email: str | None = Field(default=None, max_length=254)
    date_of_birth: date | None = None
    availability_status: Literal["Available to Play", "Busy", "In a Match"] | None = None
    # Accept the shorter names used by older clients while exposing the
    # canonical availability_status field in responses.
    status: Literal["Available to Play", "Busy", "In a Match"] | None = None
    availability: Literal["Available to Play", "Busy", "In a Match"] | None = None
    experience: Literal["Beginner", "Intermediate", "Advanced", "Professional"] | None = None
    gender: Literal["Male", "Female", "Other"] | None = None
    preferred_sports: list[str] | None = None


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=200)


class VenueInput(BaseModel):
    name: str
    address: str
    city: str = "Pune"
    latitude: float
    longitude: float


class SessionInput(BaseModel):
    sport_id: int
    title: str = Field(min_length=3, max_length=120)
    kind: Literal["match", "activity"]
    starts_at: datetime
    venue_id: int
    capacity: int = Field(ge=2, le=100)
    description: str = ""


class TournamentInput(BaseModel):
    sport_id: int
    title: str = Field(min_length=3, max_length=120)
    starts_at: datetime
    venue_id: int | None = None
    ends_at: datetime | None = None
    capacity: int = Field(default=64, ge=2, le=10_000)
    description: str = ""


class RegistrationInput(BaseModel):
    team_name: str | None = Field(default=None, max_length=120)


class ConnectionInput(BaseModel):
    user_id: int


class ConnectionUpdate(BaseModel):
    status: Literal["accepted", "rejected"]


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY,
 username TEXT UNIQUE NOT NULL,
 display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 email TEXT UNIQUE,
 phone TEXT UNIQUE,
 date_of_birth TEXT,
 gender TEXT NOT NULL DEFAULT 'Other',
 experience TEXT NOT NULL DEFAULT 'Beginner',
 preferred_sports TEXT NOT NULL DEFAULT '[]',
 availability_status TEXT NOT NULL DEFAULT 'Available to Play',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sports (
 id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, category TEXT NOT NULL,
 positions TEXT NOT NULL, emoji TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS venues (
 id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, address TEXT NOT NULL,
 city TEXT NOT NULL, latitude REAL NOT NULL, longitude REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS players (
 id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE, name TEXT NOT NULL,
 sport_id INTEGER NOT NULL, position TEXT NOT NULL, skill TEXT NOT NULL,
 gender TEXT, age INTEGER, date_of_birth TEXT, rating REAL, fitness INTEGER,
 status TEXT NOT NULL DEFAULT 'Available to Play',
 availability_status TEXT NOT NULL DEFAULT 'Available to Play',
 venue_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id),
 FOREIGN KEY(sport_id) REFERENCES sports(id), FOREIGN KEY(venue_id) REFERENCES venues(id)
);
CREATE TABLE IF NOT EXISTS sessions (
 id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('match','activity')),
 sport_id INTEGER NOT NULL, title TEXT NOT NULL, starts_at TEXT NOT NULL,
 venue_id INTEGER NOT NULL, capacity INTEGER NOT NULL, description TEXT NOT NULL DEFAULT '',
 created_by INTEGER, created_at TEXT NOT NULL,
 FOREIGN KEY(sport_id) REFERENCES sports(id), FOREIGN KEY(venue_id) REFERENCES venues(id),
 FOREIGN KEY(created_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS session_participants (
 session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, joined_at TEXT NOT NULL,
 PRIMARY KEY(session_id, user_id), FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS tournaments (
 id INTEGER PRIMARY KEY, sport_id INTEGER NOT NULL, title TEXT NOT NULL,
 starts_at TEXT NOT NULL, ends_at TEXT, venue_id INTEGER, capacity INTEGER NOT NULL,
 description TEXT NOT NULL DEFAULT '', created_by INTEGER NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(sport_id) REFERENCES sports(id), FOREIGN KEY(venue_id) REFERENCES venues(id),
 FOREIGN KEY(created_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS tournament_registrations (
 tournament_id INTEGER NOT NULL, user_id INTEGER NOT NULL, team_name TEXT,
 status TEXT NOT NULL DEFAULT 'registered', registered_at TEXT NOT NULL,
 PRIMARY KEY(tournament_id, user_id), FOREIGN KEY(tournament_id) REFERENCES tournaments(id) ON DELETE CASCADE,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS connections (
 id INTEGER PRIMARY KEY, requester_id INTEGER NOT NULL, addressee_id INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected')),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(requester_id, addressee_id),
 FOREIGN KEY(requester_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(addressee_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, type TEXT NOT NULL,
 title TEXT NOT NULL, message TEXT NOT NULL, data_json TEXT NOT NULL DEFAULT '{}',
 read_at TEXT, created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_sport_start ON sessions(sport_id, starts_at);
CREATE INDEX IF NOT EXISTS idx_players_sport_position ON players(sport_id, position);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at);
CREATE TABLE IF NOT EXISTS schema_migrations (
 version INTEGER PRIMARY KEY,
 applied_at TEXT NOT NULL
);
"""

SPORTS = [
    ("Cricket", "group", "Batsman,Bowler,All-rounder,Wicketkeeper", "🏏"),
    ("Football", "group", "Forward,Midfielder,Defender,Goalkeeper", "⚽"),
    ("Basketball", "group", "Point Guard,Shooting Guard,Small Forward,Power Forward,Center", "🏀"),
    ("Pickleball", "individual", "Singles,Doubles", "🏓"),
    ("Badminton", "individual", "Singles,Doubles", "🏸"),
    ("Walking", "fitness", "Buddy", "🚶"), ("Running", "fitness", "Buddy", "🏃"),
    ("Yoga", "fitness", "Buddy", "🧘"), ("Gym", "fitness", "Buddy", "🏋️"),
    ("Cycling", "fitness", "Buddy", "🚴"),
]
VENUES = [
    ("Community Sports Ground", "Shivaji Nagar, Pune, Maharashtra", "Pune", 18.5308, 73.8475),
    ("University Turf", "Ganeshkhind, Pune, Maharashtra", "Pune", 18.5482, 73.8267),
    ("City Indoor Arena", "Kothrud, Pune, Maharashtra", "Pune", 18.5074, 73.8077),
    ("Riverfront Track", "Bund Garden Road, Pune, Maharashtra", "Pune", 18.5362, 73.8944),
    ("Balewadi Sports Complex", "Balewadi, Pune, Maharashtra", "Pune", 18.5765, 73.7395),
    ("Aundh Community Court", "Aundh, Pune, Maharashtra", "Pune", 18.5590, 73.8070),
]
def add_column_if_missing(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
):
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def migrate_legacy_users(connection: sqlite3.Connection):
    """Bring prototype databases up to date and clear their demo records once."""
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sessions_legacy'"
    ).fetchone():
        connection.execute("DROP TABLE IF EXISTS session_participants")
        connection.execute("DROP TABLE sessions_legacy")
        connection.execute("""CREATE TABLE session_participants (
            session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, joined_at TEXT NOT NULL,
            PRIMARY KEY(session_id, user_id), FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
    # Databases created by the prototype did not have credentials.  Keep those
    # catalogue-era rows readable but never make them usable for login.
    if columns and "username" not in columns:
        connection.execute("ALTER TABLE users ADD COLUMN username TEXT")
    if columns and "password_hash" not in columns:
        connection.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
    if columns and "username" not in columns:
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        for row in connection.execute("SELECT id FROM users WHERE username IS NULL"):
            connection.execute("UPDATE users SET username=? WHERE id=?", (f"legacy_{row['id']}", row["id"]))
    add_column_if_missing(connection, "users", "date_of_birth", "TEXT")
    add_column_if_missing(connection, "users", "experience", "TEXT NOT NULL DEFAULT 'Beginner'")
    add_column_if_missing(connection, "users", "gender", "TEXT NOT NULL DEFAULT 'Other'")
    add_column_if_missing(connection, "users", "preferred_sports", "TEXT NOT NULL DEFAULT '[]'")
    add_column_if_missing(
        connection, "users", "availability_status",
        "TEXT NOT NULL DEFAULT 'Available to Play'",
    )
    connection.execute(
        "UPDATE users SET availability_status='Available to Play' "
        "WHERE availability_status IS NULL OR availability_status NOT IN (?,?,?)",
        AVAILABILITY_STATUSES,
    )
    add_column_if_missing(connection, "players", "date_of_birth", "TEXT")
    add_column_if_missing(
        connection, "players", "status",
        "TEXT NOT NULL DEFAULT 'Available to Play'",
    )
    add_column_if_missing(
        connection, "players", "availability_status",
        "TEXT NOT NULL DEFAULT 'Available to Play'",
    )
    connection.execute(
        "UPDATE players SET availability_status=COALESCE(status,'Available to Play') "
        "WHERE availability_status IS NULL OR availability_status NOT IN (?,?,?)",
        AVAILABILITY_STATUSES,
    )
    connection.execute(
        "UPDATE players SET status='Available to Play' "
        "WHERE status IS NULL OR status NOT IN (?,?,?)",
        AVAILABILITY_STATUSES,
    )
    connection.execute(
        "UPDATE players SET position='Not set' "
        "WHERE user_id IS NOT NULL AND position='Midfielder'"
    )
    session_columns = {row["name"]: row for row in connection.execute("PRAGMA table_info(sessions)")}
    if session_columns.get("created_by") and session_columns["created_by"]["notnull"]:
        connection.execute("DELETE FROM session_participants")
        connection.execute("DROP TABLE sessions")
        connection.execute("""CREATE TABLE sessions (
            id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('match','activity')),
            sport_id INTEGER NOT NULL, title TEXT NOT NULL, starts_at TEXT NOT NULL,
            venue_id INTEGER NOT NULL, capacity INTEGER NOT NULL, description TEXT NOT NULL DEFAULT '',
            created_by INTEGER, created_at TEXT NOT NULL,
            FOREIGN KEY(sport_id) REFERENCES sports(id), FOREIGN KEY(venue_id) REFERENCES venues(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )""")
    # Older releases shipped a demo account, players, sessions and activity
    # rows.  Clear those rows exactly once; data created after this migration
    # is retained across restarts.
    if not connection.execute("SELECT 1 FROM schema_migrations WHERE version=1").fetchone():
        for table in (
            "session_participants",
            "tournament_registrations",
            "notifications",
            "connections",
            "activities",
            "sessions",
            "tournaments",
            "players",
            "users",
        ):
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone():
                connection.execute(f"DELETE FROM {table}")
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES(1,?)",
            (now().isoformat(),),
        )
    # Early frontend versions accepted date labels without a year, which
    # SQLite/Python stored as year 2001. Preserve the chosen month/day/time
    # while restoring those sessions to the current calendar year.
    for session in connection.execute("SELECT id, starts_at FROM sessions").fetchall():
        try:
            starts_at = datetime.fromisoformat(session["starts_at"])
        except (TypeError, ValueError):
            continue
        if starts_at.year == 2001:
            try:
                corrected = starts_at.replace(year=now().year)
            except ValueError:
                continue
            connection.execute(
                "UPDATE sessions SET starts_at=? WHERE id=?",
                (corrected.isoformat(), session["id"]),
            )
    # Hosts are participants by default, while remaining free to leave later.
    connection.execute(
        """INSERT OR IGNORE INTO session_participants(session_id, user_id, joined_at)
           SELECT id, created_by, created_at FROM sessions
           WHERE created_by IS NOT NULL"""
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_sessions_sport_start ON sessions(sport_id, starts_at)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_players_sport_position ON players(sport_id, position)")


def seed(connection: sqlite3.Connection):
    """Seed only the sports and venues catalogues."""
    connection.executemany("INSERT OR IGNORE INTO sports(name, category, positions, emoji) VALUES(?,?,?,?)", SPORTS)
    connection.executemany("INSERT OR IGNORE INTO venues(name,address,city,latitude,longitude) VALUES(?,?,?,?,?)", VENUES)


@app.on_event("startup")
def startup():
    with db() as connection:
        connection.executescript(SCHEMA)
        migrate_legacy_users(connection)
        seed(connection)


def public_user(user: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    result = {
        key: user[key]
        for key in (
            "id", "username", "display_name", "email", "date_of_birth", "experience", "gender", "preferred_sports",
            "availability_status", "created_at",
        )
        if key in user.keys()
    }
    result["age"] = calculate_age(result.get("date_of_birth"))
    try:
        result["preferred_sports"] = json.loads(result.get("preferred_sports") or "[]")
    except (TypeError, ValueError):
        result["preferred_sports"] = []
    result["status"] = result.get("availability_status") or "Available to Play"
    result["availability"] = result["status"]
    return result


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/signup", status_code=status.HTTP_201_CREATED)
@app.post("/auth/register", status_code=status.HTTP_201_CREATED, include_in_schema=False)
@app.post("/signup", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def signup(payload: SignupInput):
    username = payload.username.strip().lower()
    display_name = payload.display_name.strip()
    email = payload.email.strip().lower() if payload.email else None

    if not username:
        raise HTTPException(422, "Username is required")
    if not re.fullmatch(r"[a-z0-9_-]{3,40}", username):
        raise HTTPException(422, "Username must be 3-40 characters using letters, numbers, underscores, or hyphens")
    if not display_name:
        raise HTTPException(422, "Display name is required")

    validate_date_of_birth(payload.date_of_birth)

    with db() as connection:
        preferred_sports = validate_signup_preferences(
            connection,
            payload.preferred_sports,
        )
        try:
            cursor = connection.execute(
                """INSERT INTO users(
                    username,display_name,password_hash,email,date_of_birth,
                    experience,gender,preferred_sports,availability_status,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    username,
                    display_name,
                    password_hash(payload.password),
                    email,
                    payload.date_of_birth.isoformat() if payload.date_of_birth else None,
                    payload.experience,
                    payload.gender,
                    json.dumps(preferred_sports),
                    "Available to Play",
                    now().isoformat(),
                ),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username or email is already registered")

        user = connection.execute(
            "SELECT * FROM users WHERE id=?",
            (cursor.lastrowid,),
        ).fetchone()

        preferred_match_sport = None
        for preference in preferred_sports:
            preferred_match_sport = connection.execute(
                """SELECT id, name FROM sports
                   WHERE name=? AND category IN ('group', 'individual')""",
                (preference,),
            ).fetchone()
            if preferred_match_sport:
                break

        if preferred_match_sport:
            connection.execute(
                """INSERT INTO players(
                    user_id,name,sport_id,position,skill,gender,age,date_of_birth,
                    rating,fitness,status,availability_status
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cursor.lastrowid,
                    display_name,
                    preferred_match_sport["id"],
                    "Not set",
                    payload.experience,
                    payload.gender,
                    calculate_age(payload.date_of_birth),
                    payload.date_of_birth.isoformat() if payload.date_of_birth else None,
                    5.0,
                    50,
                    "Available to Play",
                    "Available to Play",
                ),
            )

    return {
        "access_token": make_token(user["id"]),
        "token_type": "bearer",
        "user": public_user(user),
    }


@app.post("/auth/login")
@app.post("/login", include_in_schema=False)
def login(payload: LoginInput):
    identifier = payload.username.strip().lower()
    with db() as connection:
        user = connection.execute(
            "SELECT * FROM users WHERE lower(username)=? OR lower(email)=?", (identifier, identifier)
        ).fetchone()
    if not user or not password_matches(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"access_token": make_token(user["id"]), "token_type": "bearer", "user": public_user(user)}


@app.get("/auth/me")
@app.get("/auth/profile", include_in_schema=False)
@app.get("/profile", include_in_schema=False)
@app.get("/users/me", include_in_schema=False)
@app.get("/me", include_in_schema=False)
def me(user: dict[str, Any] = Depends(current_user)):
    return public_user(user)


@app.patch("/auth/me")
@app.put("/auth/me", include_in_schema=False)
@app.patch("/auth/profile", include_in_schema=False)
@app.put("/auth/profile", include_in_schema=False)
@app.patch("/profile", include_in_schema=False)
@app.put("/profile", include_in_schema=False)
@app.patch("/users/me", include_in_schema=False)
@app.put("/users/me", include_in_schema=False)
def update_profile(payload: ProfileUpdate, user: dict[str, Any] = Depends(current_user)):
    owner_id = user_id(user)
    validate_date_of_birth(payload.date_of_birth)
    updates: dict[str, Any] = {}
    if payload.display_name is not None:
        display_name = payload.display_name.strip()
        if not display_name:
            raise HTTPException(422, "Display name is required")
        updates["display_name"] = display_name
    if payload.email is not None:
        updates["email"] = payload.email.strip().lower() or None
    if payload.date_of_birth is not None:
        updates["date_of_birth"] = payload.date_of_birth.isoformat()
    if payload.experience is not None:
        updates["experience"] = payload.experience
    if payload.gender is not None:
        updates["gender"] = payload.gender
    if payload.preferred_sports is not None:
        updates["preferred_sports"] = json.dumps(payload.preferred_sports)
    availability = payload.availability_status or payload.status or payload.availability
    if availability:
        updates["availability_status"] = availability
    with db() as connection:
        try:
            if updates:
                assignments = ", ".join(f"{column}=?" for column in updates)
                connection.execute(
                    f"UPDATE users SET {assignments} WHERE id=?",
                    (*updates.values(), owner_id),
                )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Email is already registered")
        if "display_name" in updates:
            connection.execute(
                "UPDATE players SET name=? WHERE user_id=?",
                (updates["display_name"], owner_id),
            )
        if "date_of_birth" in updates:
            connection.execute(
                "UPDATE players SET date_of_birth=?,age=? WHERE user_id=?",
                (updates["date_of_birth"], calculate_age(updates["date_of_birth"]), owner_id),
            )
        if "experience" in updates:
            connection.execute(
                "UPDATE players SET skill=? WHERE user_id=?",
                (updates["experience"], owner_id),
            )
        if "gender" in updates:
            connection.execute(
                "UPDATE players SET gender=? WHERE user_id=?",
                (updates["gender"], owner_id),
            )
        if "availability_status" in updates:
            connection.execute(
                """UPDATE players
                   SET status=?, availability_status=?
                   WHERE user_id=?""",
                (updates["availability_status"], updates["availability_status"], owner_id),
            )
        updated = connection.execute(
            """SELECT id, username, display_name, email, date_of_birth, experience, gender,
                      preferred_sports,
                      availability_status, created_at
               FROM users WHERE id=?""",
            (owner_id,),
        ).fetchone()
    return public_user(updated)



@app.delete("/auth/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(user: dict[str, Any] = Depends(current_user)):
    owner_id = user_id(user)

    with db() as connection:
        try:
            connection.execute("DELETE FROM session_participants WHERE user_id=?", (owner_id,))
            connection.execute("DELETE FROM sessions WHERE created_by=?", (owner_id,))
            connection.execute("DELETE FROM tournament_registrations WHERE user_id=?", (owner_id,))
            connection.execute("DELETE FROM tournaments WHERE created_by=?", (owner_id,))
            connection.execute("DELETE FROM players WHERE user_id=?", (owner_id,))
            connection.execute("DELETE FROM users WHERE id=?", (owner_id,))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="The account could not be deleted because related data still exists.",
            ) from exc

        if connection.total_changes == 0:
            raise HTTPException(status_code=404, detail="User not found")

    return {"ok": True, "msg": "Friend removed."}

@app.get("/users")
def list_users(search: str | None = None, user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        pattern = f"%{search.strip()}%" if search else "%"
        return rows(
            connection,
            """SELECT id,username,display_name FROM users
               WHERE id != ? AND (username LIKE ? OR display_name LIKE ?)
               ORDER BY display_name LIMIT 50""",
            (user_id(user), pattern, pattern),
        )


@app.get("/sports")
def list_sports():
    with db() as connection:
        data = rows(connection, "SELECT id,name,category,positions,emoji FROM sports ORDER BY name")
    for item in data:
        item["positions"] = item["positions"].split(",")
    return data


@app.get("/venues")
def list_venues(city: str | None = None):
    with db() as connection:
        return rows(connection, "SELECT * FROM venues WHERE (? IS NULL OR city=?) ORDER BY name", (city, city))


@app.get("/players")
def list_players(sport: str | None = None, position: str | None = None, skill: str | None = None):
    query = """SELECT p.*, s.name AS sport, v.name AS venue_name, v.city, v.address
               , u.date_of_birth AS user_date_of_birth,
                 u.availability_status AS user_availability_status,
                 u.preferred_sports AS user_preferred_sports
               FROM players p JOIN sports s ON s.id=p.sport_id LEFT JOIN venues v ON v.id=p.venue_id
               LEFT JOIN users u ON u.id=p.user_id
               WHERE (? IS NULL OR s.name=?) AND (? IS NULL OR p.position=?)
                 AND (? IS NULL OR p.skill=?) ORDER BY p.rating DESC"""
    with db() as connection:
        result = rows(connection, query, (sport, sport, position, position, skill, skill))
    for item in result:
        item["date_of_birth"] = item.pop("user_date_of_birth", None) or item.get("date_of_birth")
        try:
            item["preferred_sports"] = json.loads(item.pop("user_preferred_sports", "[]") or "[]")
        except (TypeError, ValueError):
            item["preferred_sports"] = []
        item["age"] = calculate_age(item["date_of_birth"]) if item["date_of_birth"] else item.get("age")
        item["availability_status"] = (
            item.pop("user_availability_status", None)
            or item.get("availability_status")
            or item.get("status")
            or "Available to Play"
        )
        item["status"] = item["availability_status"]
        item["availability"] = item["availability_status"]
    return result


@app.get("/filters/players")
def player_filters(sport: str | None = None):
    with db() as connection:
        return {
            "sports": rows(connection, "SELECT name FROM sports ORDER BY name"),
            "positions": rows(connection, """SELECT DISTINCT p.position FROM players p
                JOIN sports s ON s.id=p.sport_id WHERE (? IS NULL OR s.name=?) ORDER BY p.position""", (sport, sport)),
        }


@app.get("/sessions")
def list_sessions(
    kind: Literal["match", "activity"] | None = None,
    sport: str | None = None,
    viewer_id: int | None = Depends(optional_user_id),
):
    query = """SELECT se.*, s.name AS sport, v.name AS venue_name, v.address AS venue_address,
      COUNT(sp.user_id) AS joined FROM sessions se JOIN sports s ON s.id=se.sport_id JOIN venues v ON v.id=se.venue_id
      LEFT JOIN session_participants sp ON sp.session_id=se.id
      WHERE (? IS NULL OR se.kind=?) AND (? IS NULL OR s.name=?)
      GROUP BY se.id ORDER BY se.starts_at"""
    with db() as connection:
        result = rows(connection, query, (kind, kind, sport, sport))
        for item in result:
            participants = connection.execute(
                "SELECT user_id FROM session_participants WHERE session_id=? ORDER BY joined_at",
                (item["id"],),
            ).fetchall()
            item["participant_ids"] = [participant["user_id"] for participant in participants]
            item["joined_by_me"] = viewer_id is not None and viewer_id in item["participant_ids"]
        return result


@app.post("/sessions", status_code=status.HTTP_201_CREATED)
def create_session(payload: SessionInput, user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        if not connection.execute("SELECT 1 FROM sports WHERE id=?", (payload.sport_id,)).fetchone():
            raise HTTPException(422, "Unknown sport")
        if not connection.execute("SELECT 1 FROM venues WHERE id=?", (payload.venue_id,)).fetchone():
            raise HTTPException(422, "Unknown venue")
        cursor = connection.execute(
            "INSERT INTO sessions(kind,sport_id,title,starts_at,venue_id,capacity,description,created_by,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (payload.kind, payload.sport_id, payload.title, payload.starts_at.isoformat(), payload.venue_id,
             payload.capacity, payload.description, user_id(user), now().isoformat()),
        )
        connection.execute(
            "INSERT INTO session_participants(session_id,user_id,joined_at) VALUES(?,?,?)",
            (cursor.lastrowid, user_id(user), now().isoformat()),
        )
    return {"id": cursor.lastrowid}


def get_session(connection: sqlite3.Connection, session_id: int):
    result = connection.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not result:
        raise HTTPException(404, "Session not found")
    return result


@app.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(session_id: int, user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        session = get_session(connection, session_id)
        if session["created_by"] != user_id(user):
            raise HTTPException(403, "Only the host can delete this match")
        if datetime.fromisoformat(session["starts_at"]) <= now():
            raise HTTPException(409, "A match cannot be deleted after it starts")
        connection.execute("DELETE FROM sessions WHERE id=?", (session_id,))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


class SessionInviteInput(BaseModel):
    user_ids: list[int] = Field(min_length=1, max_length=50)


@app.post("/sessions/{session_id}/invite")
def invite_to_session(
    session_id: int,
    payload: SessionInviteInput,
    user: dict[str, Any] = Depends(current_user),
):
    notified = []
    with db() as connection:
        session = get_session(connection, session_id)
        if session["created_by"] != user_id(user):
            raise HTTPException(403, "Only the host can invite players")
        timestamp = now().isoformat()
        for invited_id in set(payload.user_ids):
            if invited_id == user_id(user):
                continue
            if not connection.execute("SELECT 1 FROM users WHERE id=?", (invited_id,)).fetchone():
                continue
            cursor = connection.execute(
                "INSERT INTO notifications(user_id,type,title,message,data_json,created_at) VALUES(?,?,?,?,?,?)",
                (invited_id, "session_invite", "Session invitation",
                 f"{user['display_name']} invited you to {session['title']}",
                 json.dumps({"session_id": session_id, "kind": session["kind"]}), timestamp),
            )
            notified.append((invited_id, cursor.lastrowid))
    for invited_id, notification_id in notified:
        publish_notification(invited_id, notification_id)
    return {"message": "Invitations sent"}


@app.post("/sessions/{session_id}/join")
def join_session(session_id: int, user: dict[str, Any] = Depends(current_user)):
    notification_id = None
    with db() as connection:
        session = get_session(connection, session_id)
        count = connection.execute("SELECT COUNT(*) FROM session_participants WHERE session_id=?", (session_id,)).fetchone()[0]
        already = connection.execute(
            "SELECT 1 FROM session_participants WHERE session_id=? AND user_id=?", (session_id, user_id(user))
        ).fetchone()
        if already:
            raise HTTPException(409, "You already joined this session")
        if count >= session["capacity"]:
            raise HTTPException(409, "This session is full")
        connection.execute(
            "INSERT INTO session_participants(session_id,user_id,joined_at) VALUES(?,?,?)",
            (session_id, user_id(user), now().isoformat()),
        )
        cursor = connection.execute(
            "INSERT INTO notifications(user_id,type,title,message,data_json,created_at) VALUES(?,?,?,?,?,?)",
            (user_id(user), "session_joined", "Session joined",
             f"You joined {session['title']}", json.dumps({"session_id": session_id}), now().isoformat()),
        )
        notification_id = cursor.lastrowid
    publish_notification(user_id(user), notification_id)
    return {"message": "Joined successfully", "session_id": session_id}


@app.delete("/sessions/{session_id}/join", status_code=status.HTTP_204_NO_CONTENT)
def leave_session(session_id: int, user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        session = get_session(connection, session_id)
        starts_at = datetime.fromisoformat(session["starts_at"])
        if datetime.now(starts_at.tzinfo) >= starts_at - timedelta(hours=2):
            raise HTTPException(409, "You can only leave more than two hours before the session starts")
        deleted = connection.execute(
            "DELETE FROM session_participants WHERE session_id=? AND user_id=?", (session_id, user_id(user))
        ).rowcount
        if not deleted:
            if session["created_by"] == user_id(user):
                return Response(status_code=status.HTTP_204_NO_CONTENT)
            raise HTTPException(404, "You have not joined this session")
        cursor = connection.execute(
            "INSERT INTO notifications(user_id,type,title,message,data_json,created_at) VALUES(?,?,?,?,?,?)",
            (user_id(user), "session_left", "Session left",
             f"You left {session['title']}", json.dumps({"session_id": session_id}), now().isoformat()),
        )
        notification_id = cursor.lastrowid
    publish_notification(user_id(user), notification_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def tournament_result(connection: sqlite3.Connection, tournament_id: int):
    tournament = connection.execute(
        """SELECT t.*, s.name AS sport, v.name AS venue_name,
           COUNT(tr.user_id) AS registered
           FROM tournaments t JOIN sports s ON s.id=t.sport_id
           LEFT JOIN venues v ON v.id=t.venue_id
           LEFT JOIN tournament_registrations tr ON tr.tournament_id=t.id
           WHERE t.id=? GROUP BY t.id""", (tournament_id,)
    ).fetchone()
    if not tournament:
        raise HTTPException(404, "Tournament not found")
    return dict(tournament)


@app.get("/tournaments")
def list_tournaments(sport: str | None = None, viewer_id: int | None = Depends(optional_user_id)):
    with db() as connection:
        query = """SELECT t.*, s.name AS sport, v.name AS venue_name, COUNT(tr.user_id) AS registered
                   FROM tournaments t JOIN sports s ON s.id=t.sport_id LEFT JOIN venues v ON v.id=t.venue_id
                   LEFT JOIN tournament_registrations tr ON tr.tournament_id=t.id
                   WHERE (? IS NULL OR s.name=?) GROUP BY t.id ORDER BY t.starts_at"""
        result = rows(connection, query, (sport, sport))
        for item in result:
            item["registered_by_me"] = bool(
                viewer_id is not None and connection.execute(
                    "SELECT 1 FROM tournament_registrations WHERE tournament_id=? AND user_id=?",
                    (item["id"], viewer_id),
                ).fetchone()
            )
        return result


@app.post("/tournaments", status_code=status.HTTP_201_CREATED)
def create_tournament(payload: TournamentInput, user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        if not connection.execute("SELECT 1 FROM sports WHERE id=?", (payload.sport_id,)).fetchone():
            raise HTTPException(422, "Unknown sport")
        if payload.venue_id and not connection.execute("SELECT 1 FROM venues WHERE id=?", (payload.venue_id,)).fetchone():
            raise HTTPException(422, "Unknown venue")
        cursor = connection.execute(
            """INSERT INTO tournaments(sport_id,title,starts_at,ends_at,venue_id,capacity,description,created_by,created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (payload.sport_id, payload.title, payload.starts_at.isoformat(),
             payload.ends_at.isoformat() if payload.ends_at else None, payload.venue_id, payload.capacity,
             payload.description, user_id(user), now().isoformat()),
        )
        tournament_id = cursor.lastrowid
        return tournament_result(connection, tournament_id)


@app.get("/tournaments/{tournament_id}")
def get_tournament(tournament_id: int):
    with db() as connection:
        return tournament_result(connection, tournament_id)


@app.delete("/tournaments/{tournament_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_tournament(tournament_id: int, user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        tournament = connection.execute(
            "SELECT * FROM tournaments WHERE id=?", (tournament_id,)
        ).fetchone()
        if not tournament:
            raise HTTPException(404, "Tournament not found")
        if tournament["created_by"] != user_id(user):
            raise HTTPException(403, "Only the tournament host can delete it")
        if datetime.fromisoformat(tournament["starts_at"]) <= now():
            raise HTTPException(409, "A tournament cannot be deleted after it starts")
        connection.execute("DELETE FROM tournaments WHERE id=?", (tournament_id,))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/tournaments/{tournament_id}/register", status_code=status.HTTP_201_CREATED)
@app.post("/tournaments/{tournament_id}/registrations", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def register_tournament(tournament_id: int, payload: RegistrationInput | None = None, user: dict[str, Any] = Depends(current_user)):
    notification_id = None
    with db() as connection:
        tournament = connection.execute("SELECT * FROM tournaments WHERE id=?", (tournament_id,)).fetchone()
        if not tournament:
            raise HTTPException(404, "Tournament not found")
        count = connection.execute("SELECT COUNT(*) FROM tournament_registrations WHERE tournament_id=?", (tournament_id,)).fetchone()[0]
        if count >= tournament["capacity"]:
            raise HTTPException(409, "This tournament is full")
        try:
            connection.execute(
                "INSERT INTO tournament_registrations(tournament_id,user_id,team_name,registered_at) VALUES(?,?,?,?)",
                (tournament_id, user_id(user), payload.team_name if payload else None, now().isoformat()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "You are already registered")
        cursor = connection.execute(
            "INSERT INTO notifications(user_id,type,title,message,data_json,created_at) VALUES(?,?,?,?,?,?)",
            (user_id(user), "tournament_registration", "Tournament registration confirmed",
             f"You registered for {tournament['title']}", json.dumps({"tournament_id": tournament_id}), now().isoformat()),
        )
        notification_id = cursor.lastrowid
        host_notification_id = None
        if tournament["created_by"] != user_id(user):
            host_cursor = connection.execute(
                "INSERT INTO notifications(user_id,type,title,message,data_json,created_at) VALUES(?,?,?,?,?,?)",
                (tournament["created_by"], "tournament_registration_received", "Tournament registration",
                 f"{user['display_name']} registered for {tournament['title']}",
                 json.dumps({"tournament_id": tournament_id}), now().isoformat()),
            )
            host_notification_id = host_cursor.lastrowid
    publish_notification(user_id(user), notification_id)
    if host_notification_id is not None:
        publish_notification(tournament["created_by"], host_notification_id)
    return {"message": "Registered successfully", "tournament_id": tournament_id}


@app.delete("/tournaments/{tournament_id}/register", status_code=status.HTTP_204_NO_CONTENT)
@app.delete("/tournaments/{tournament_id}/registrations", status_code=status.HTTP_204_NO_CONTENT, include_in_schema=False)
def unregister_tournament(tournament_id: int, user: dict[str, Any] = Depends(current_user)):
    owner_id = user_id(user)
    with db() as connection:
        tournament = connection.execute("SELECT * FROM tournaments WHERE id=?", (tournament_id,)).fetchone()
        if not tournament:
            raise HTTPException(404, "Tournament not found")
        deleted = connection.execute(
            "DELETE FROM tournament_registrations WHERE tournament_id=? AND user_id=?", (tournament_id, owner_id)
        ).rowcount
        if not deleted:
            raise HTTPException(404, "You are not registered for this tournament")
        host_notification_id = None
        if tournament["created_by"] != owner_id:
            cursor = connection.execute(
                "INSERT INTO notifications(user_id,type,title,message,data_json,created_at) VALUES(?,?,?,?,?,?)",
                (tournament["created_by"], "tournament_registration_cancelled", "Tournament registration cancelled",
                 f"{user['display_name']} left {tournament['title']}",
                 json.dumps({"tournament_id": tournament_id}), now().isoformat()),
            )
            host_notification_id = cursor.lastrowid
    if host_notification_id is not None:
        publish_notification(tournament["created_by"], host_notification_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/tournaments/{tournament_id}/registrations")
def list_registrations(tournament_id: int, user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        if not connection.execute("SELECT 1 FROM tournaments WHERE id=?", (tournament_id,)).fetchone():
            raise HTTPException(404, "Tournament not found")
        return rows(
            connection,
            """SELECT tr.user_id, tr.team_name, tr.status, tr.registered_at,
                      u.username, u.display_name
               FROM tournament_registrations tr JOIN users u ON u.id=tr.user_id
               WHERE tr.tournament_id=? ORDER BY tr.registered_at""",
            (tournament_id,),
        )


def notification(connection: sqlite3.Connection, notification_id: int, owner_id: int):
    item = connection.execute("SELECT * FROM notifications WHERE id=? AND user_id=?", (notification_id, owner_id)).fetchone()
    if not item:
        raise HTTPException(404, "Notification not found")
    result = dict(item)
    result["data"] = json.loads(result.pop("data_json") or "{}")
    result["read"] = result["read_at"] is not None
    return result


@app.get("/notifications")
def list_notifications(
    unread_only: bool = Query(False, alias="unread"),
    user: dict[str, Any] = Depends(current_user),
):
    where = "AND read_at IS NULL" if unread_only else ""
    with db() as connection:
        result = rows(connection, f"SELECT * FROM notifications WHERE user_id=? {where} ORDER BY created_at DESC", (user_id(user),))
    for item in result:
        item["data"] = json.loads(item.pop("data_json") or "{}")
        item["read"] = item["read_at"] is not None
    return result


@app.patch("/notifications/{notification_id}/read")
@app.post("/notifications/{notification_id}/read", include_in_schema=False)
def mark_notification_read(notification_id: int, user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        if not connection.execute("SELECT 1 FROM notifications WHERE id=? AND user_id=?", (notification_id, user_id(user))).fetchone():
            raise HTTPException(404, "Notification not found")
        connection.execute("UPDATE notifications SET read_at=? WHERE id=?", (now().isoformat(), notification_id))
        return notification(connection, notification_id, user_id(user))


@app.post("/notifications/read-all")
def mark_all_notifications_read(user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        connection.execute("UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL", (now().isoformat(), user_id(user)))
    return {"message": "Notifications marked as read"}


@app.delete("/notifications/{notification_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_notification(notification_id: int, user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        deleted = connection.execute(
            "DELETE FROM notifications WHERE id=? AND user_id=?",
            (notification_id, user_id(user)),
        ).rowcount
        if not deleted:
            raise HTTPException(404, "Notification not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.delete("/notifications", status_code=status.HTTP_204_NO_CONTENT)
def delete_all_notifications(user: dict[str, Any] = Depends(current_user)):
    with db() as connection:
        connection.execute("DELETE FROM notifications WHERE user_id=?", (user_id(user),))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def connection_result(connection: sqlite3.Connection, row: sqlite3.Row, owner_id: int):
    result = dict(row)
    result["user"] = dict(connection.execute(
        "SELECT id,username,display_name,email FROM users WHERE id=?",
        (row["addressee_id"] if row["requester_id"] == owner_id else row["requester_id"],),
    ).fetchone())
    return result


@app.get("/connections")
def list_connections(
    status_filter: str | None = Query(None, alias="status"),
    user: dict[str, Any] = Depends(current_user),
):
    with db() as connection:
        query = """SELECT * FROM connections WHERE (requester_id=? OR addressee_id=?)
                   AND (? IS NULL OR status=?) ORDER BY updated_at DESC"""
        records = connection.execute(query, (user_id(user), user_id(user), status_filter, status_filter)).fetchall()
        return [connection_result(connection, record, user_id(user)) for record in records]


@app.post("/connections", status_code=status.HTTP_201_CREATED)
def create_connection(payload: ConnectionInput, user: dict[str, Any] = Depends(current_user)):
    owner_id = user_id(user)
    if payload.user_id == owner_id:
        raise HTTPException(400, "You cannot connect with yourself")
    with db() as connection:
        if not connection.execute("SELECT 1 FROM users WHERE id=?", (payload.user_id,)).fetchone():
            raise HTTPException(404, "User not found")
        existing = connection.execute(
            "SELECT * FROM connections WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)",
            (owner_id, payload.user_id, payload.user_id, owner_id),
        ).fetchone()
        if existing:
            raise HTTPException(409, "A connection already exists")
        timestamp = now().isoformat()
        cursor = connection.execute(
            "INSERT INTO connections(requester_id,addressee_id,status,created_at,updated_at) VALUES(?,?,?, ?,?)",
            (owner_id, payload.user_id, "pending", timestamp, timestamp),
        )
        notification_cursor = connection.execute(
            "INSERT INTO notifications(user_id,type,title,message,data_json,created_at) VALUES(?,?,?,?,?,?)",
            (payload.user_id, "connection_request", "New connection request",
             f"{user['display_name']} wants to connect with you",
             json.dumps({"connection_id": cursor.lastrowid}), timestamp),
        )
        record = connection.execute("SELECT * FROM connections WHERE id=?", (cursor.lastrowid,)).fetchone()
        result = connection_result(connection, record, owner_id)
    publish_notification(payload.user_id, notification_cursor.lastrowid)
    publish_connection_change(owner_id, payload.user_id)
    return result


@app.patch("/connections/{connection_id}")
def update_connection(
    connection_id: int,
    payload: ConnectionUpdate,
    user: dict[str, Any] = Depends(current_user),
):
    owner_id = user_id(user)
    with db() as connection:
        record = connection.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone()
        if not record or owner_id not in (record["requester_id"], record["addressee_id"]):
            raise HTTPException(404, "Connection not found")
        if record["addressee_id"] != owner_id:
            raise HTTPException(403, "Only the recipient can respond to a request")
        connection.execute("UPDATE connections SET status=?,updated_at=? WHERE id=?",
                           (payload.status, now().isoformat(), connection_id))
        notification_cursor = connection.execute(
            "INSERT INTO notifications(user_id,type,title,message,data_json,created_at) VALUES(?,?,?,?,?,?)",
            (record["requester_id"], "connection_update", "Connection request updated",
             f"{user['display_name']} {payload.status} your connection request",
             json.dumps({"connection_id": connection_id, "status": payload.status}), now().isoformat()),
        )
        result = connection_result(connection, connection.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone(), owner_id)
        other_user_id = record["requester_id"]
    publish_notification(other_user_id, notification_cursor.lastrowid)
    publish_connection_change(owner_id, other_user_id)
    return result


@app.delete("/connections/by-user/{other_user_id}")
def delete_connection_by_user(other_user_id: int, user: dict[str, Any] = Depends(current_user)):
    owner_id = user_id(user)
    if other_user_id == owner_id:
        raise HTTPException(400, "You cannot remove yourself")
    with db() as connection:
        record = connection.execute(
            """SELECT * FROM connections
               WHERE ((requester_id=? AND addressee_id=?)
                  OR (requester_id=? AND addressee_id=?))
                 AND status='accepted'""",
            (owner_id, other_user_id, other_user_id, owner_id),
        ).fetchone()
        if not record:
            raise HTTPException(404, "Friend connection not found")
        connection.execute("DELETE FROM connections WHERE id=?", (record["id"],))
    publish_connection_change(owner_id, other_user_id)
    return {"ok": True, "connection_id": record["id"]}


@app.delete("/connections/{connection_id}")
def delete_connection(connection_id: int, user: dict[str, Any] = Depends(current_user)):
    owner_id = user_id(user)
    with db() as connection:
        record = connection.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone()
        if not record or owner_id not in (record["requester_id"], record["addressee_id"]):
            raise HTTPException(404, "Connection not found")
        other_user_id = record["addressee_id"] if record["requester_id"] == owner_id else record["requester_id"]
        connection.execute("DELETE FROM connections WHERE id=?", (connection_id,))
    publish_connection_change(owner_id, other_user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
