# SocketRoom

SocketRoom is a learning project for a real-time chat application built with **FastAPI, WebSockets, SQLite, SQLAlchemy, and vanilla HTML/CSS/JavaScript**.

It currently supports user registration and login, JWT-based authentication, and a global real-time chat for authenticated users.

## Features

- User registration with username, email, and password validation.
- Password hashing with Argon2.
- JWT access tokens with configurable expiration.
- Authenticated REST endpoint for retrieving the current user.
- Authenticated WebSocket connections.
- Real-time message broadcasting to connected users.
- Structured and validated WebSocket message payloads.
- Per-client outbound queues, bounded queue sizes, and send timeouts.
- Frontend session restoration, logout, connection status, and manual reconnect.
- SQLite database access through SQLAlchemy.
- Backend tests using pytest.

## Current scope and limitations

This is a learning project, not yet a production-ready chat service.

- Chat is currently **global**; separate chat rooms are not implemented.
- Messages are broadcast live but are **not persisted** in the database.
- Online presence and typing indicators are not implemented.
- WebSocket connection tracking is in application memory, so separate server processes do not share a connection manager.
- The frontend stores the access token in `sessionStorage`; JavaScript running on the same origin can access it.

## Tech stack

- **Backend:** Python, FastAPI, Uvicorn
- **Realtime:** WebSockets and asyncio
- **Database:** SQLite and SQLAlchemy
- **Validation/configuration:** Pydantic and Pydantic Settings
- **Authentication:** JWT (PyJWT) and Argon2 (`pwdlib`)
- **Frontend:** HTML, CSS, vanilla JavaScript
- **Testing:** pytest, HTTPX, pytest-timeout

## Project structure

```text
SocketRoom/
├── backend/
│   ├── app/
│   │   ├── routers/
│   │   │   ├── auth.py          # Registration, login, current-user endpoint
│   │   │   └── websocket.py     # WebSocket authentication and message handling
│   │   ├── config.py            # Environment-based settings
│   │   ├── connections.py       # Connection manager and per-client queues
│   │   ├── database.py          # SQLAlchemy engine and session dependency
│   │   ├── deps.py              # Authentication dependency for REST routes
│   │   ├── main.py              # FastAPI app, lifespan, routes, frontend mount
│   │   ├── models.py            # SQLAlchemy database models
│   │   ├── schemas.py           # Pydantic request/response schemas
│   │   └── security.py          # Password hashing and JWT helpers
│   ├── tests/
│   ├── .env.example
│   ├── requirements.txt
│   └── requirements-dev.txt
└── frontend/
    ├── index.html
    ├── style.css
    └── app.js
```

## Requirements

- Python 3.11 or a compatible modern Python version.
- Git.
- A browser with WebSocket support.

The commands below use **Git Bash on Windows**, from the repository root.

## Setup

### 1. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/Scripts/activate
```

### 2. Install dependencies

```bash
python -m pip install -r backend/requirements-dev.txt
```

### 3. Create the local environment file

```bash
cp backend/.env.example backend/.env
```

Generate a random secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Replace the placeholder `SECRET_KEY` in `backend/.env` with the generated value. Keep `.env` private and never commit it. The example file is for configuration reference only.

### 4. Start the application

From the repository root:

```bash
python -m uvicorn app.main:app --reload --app-dir backend
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser. The frontend is served by FastAPI, so the UI and API use the same origin.

Useful endpoints:

- `GET /health` — application/database health check
- `POST /auth/register` — create an account
- `POST /auth/login` — obtain an access token
- `GET /auth/me` — retrieve the authenticated user (Bearer token required)
- `/ws` — authenticated WebSocket endpoint

Interactive API documentation is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) while the application is running.

## WebSocket protocol

The client must send an authentication message as the **first WebSocket frame**:

```json
{
  "type": "auth",
  "token": "<access-token>"
}
```

After authentication, send chat messages in this format:

```json
{
  "type": "message",
  "content": "Hello, everyone!"
}
```

The server validates the payload and sets the sender from the authenticated user; clients cannot choose their own sender identity. A broadcast message has this shape:

```json
{
  "type": "message",
  "sender": "username",
  "content": "Hello, everyone!"
}
```

Message content is trimmed and must contain between 1 and 2,000 characters. Unknown fields are rejected. The current implementation closes connections for invalid authentication or message payloads and for unsupported binary data.

## Run tests

From the repository root:

```bash
python -m pytest backend/tests -v
```

To run the same command using the Windows virtual-environment interpreter explicitly:

```bash
.venv/Scripts/python.exe -m pytest backend/tests -v
```

## Development workflow

Use feature branches for changes, run the tests before opening a pull request, and keep commits focused.

Before committing, check whitespace errors and review the working tree:

```bash
git diff --check
git status
git diff
```

## Learning goals

SocketRoom is intended to practice:

- FastAPI routing and dependency injection
- Pydantic validation and settings management
- Password hashing and JWT authentication
- SQLAlchemy models and database sessions
- Async WebSocket communication and connection lifecycle management
- Queues, tasks, and handling slow clients
- Frontend/backend integration and error handling
- Automated testing and Git feature-branch workflow

## Planned improvements

Potential next milestones include more robust WebSocket failure handling, persistent message history, separate chat rooms, online presence, typing indicators, and improved deployment support. These are planned improvements, not features currently implemented.
