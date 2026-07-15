# WebHawk — Advanced C++ Excellenteam Final Project

WebHawk is a security middleware platform: every incoming request is checked for
SQL injection, XSS, and rate-limit abuse before it's forwarded to the real backend it's protecting.

## Services

| Service | Internal port | Reachable from outside Docker? |
|---|---|---|
| `middleware` | 8080 | **Yes - the only one.** This is the project's single entry point. |
| `services/users` | 8080 | No - internal only |
| `services/security-engine` | 8080 | No - internal only |
| `services/backend-registry` | 8080 | No - internal only |

Each service is an independent Drogon executable with its own `main.cc`,
`CMakeLists.txt`, and Dockerfile (`Dockerfile-security` for security-engine,
`Dockerfile-users` for users, and so on per service), and all listen on the
same internal port (8080) - that's fine because each runs in its own Docker
container with its own isolated network namespace. Only the middleware's
container publishes its port to the host; every other service is reachable
only from inside the Docker network, by service name (e.g.
`http://security-engine:8080/analyze`).

## Security notes

- **Passwords are hashed with bcrypt** (`services/users/utils/HashUtils.cc`),
  per the project spec - not a plain fast hash like SHA-256, since bcrypt's
  built-in salting and deliberately slow cost factor are what make password
  hashes resistant to brute-force/rainbow-table attacks. Requires
  `libbcrypt-dev` - already installed automatically inside `Dockerfile-users`;
  only needed manually if running the users service natively (see the bottom
  of this file).

## Prerequisites

- Docker + Docker Compose
- This project is developed inside **WSL (Ubuntu)** — not native Windows —
  but everything below runs the same way once Docker is installed.

## Setup

### 1. Clone the repo (inside WSL)

```bash
cd ~
git clone git@github.com:OrelZabriko/Advanced-Cpp-Excellenteam-WebHawk.git
cd Advanced-Cpp-Excellenteam-WebHawk
```

### 2. Create your `.env` file

All secrets and per-environment settings (DB credentials, JWT secret, rate-limit
config) live in a single `.env` file at the repo root — **not committed to git**.
Copy the template and adjust if needed:

```bash
cp .env.example .env
```

`.env.example` (committed, no real secrets) documents every variable:

```
DB_HOST=postgres
DB_PORT=5432
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=webhawk
JWT_SECRET=change_this_secret
JWT_ALGORITHM=HS256
JWT_EXPIRY_SECS=86400
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_WINDOW_SECS=60
```

- `DB_HOST=postgres` because the project runs via Docker Compose by default -
  `postgres` is the Compose service name, resolved automatically by Docker's
  internal DNS. Override it to `127.0.0.1` in your local `.env` only if
  you're temporarily running a service natively for debugging (see the
  bottom of this file).
- Config is split by ownership, all built on one shared `.env` loader:
  - `services/shared/EnvLoader.h` — reads `.env` once (used by all three below)
  - `services/shared/DbConfig.h` — `DB_*`, shared by every service that talks to Postgres
  - `services/users/utils/AuthConfig.h` — `JWT_*`, used only by users
  - `services/security-engine/utils/SecurityConfig.h` — `RATE_LIMIT_*`, used only by security-engine
- Each service's `main.cc` builds its DB connection from `DbConfig::HOST()` etc.
  in code — `config.json` no longer contains credentials, only the port it listens on.
- **`.env` syntax rule**: each line must be `KEY=VALUE` only - no spaces around
  `=`, and no trailing comment on a value line. Only a line that starts with
  `#` is treated as a comment (see `EnvLoader.h`); `DB_HOST=postgres # docker`
  would be parsed as the literal value `postgres # docker` and break the
  connection.
- `.gitignore` intentionally does **not** exclude `services/*/config.json`
  anymore - those files no longer contain credentials (see above), so they're
  safe to commit and keep in sync across the team. Only `.env` itself is excluded.
- **`.dockerignore`** (repo root) exists so `.env` never gets baked into a
  Docker image. `.gitignore` only controls what goes into *git* - it has no
  effect on what `COPY . /app` puts inside an image, so without `.dockerignore`
  the real secrets in `.env` would end up inside the built image's layers.

### 3. Run everything

```bash
docker compose up --build
```
This builds and starts every service as its own container on one Docker
network, and initializes Postgres automatically from the `.sql` files in `db/`.

**Only the middleware is reachable from outside Docker** (`localhost:8080`,
once it's built). `users`, `security-engine`, and `backend-registry` have no
external port at all - there's no meaningful way to call them directly from
outside Docker, by design. End-to-end testing happens once the middleware
exists, by hitting `localhost:8080` and letting it route the request through
the rest of the system.

## Postman

Test collections live in `postman/`. `webhawk_security_engine.postman_collection.json`
targets `/analyze` directly on port 8081 - that was written back when the
service was reachable directly. Once the middleware is live, testing should
go through it instead (`localhost:8080`), and this collection will need
updating accordingly.

## Database

Schema lives in `db/` as plain `.sql` files, loaded automatically by the
`postgres` container on first start (via `docker-entrypoint-initdb.d`).

## Debugging a single service natively (optional)

Only needed if you want to build/run one service directly on your machine,
outside Docker, for faster debugging - not the normal way to use the project.

Install locally: Drogon (course install script; confirm with
`ls /usr/local/include/drogon/drogon.h`) and `libbcrypt-dev`
(`sudo apt-get install libbcrypt-dev`, needed by the users service only).
Start Postgres yourself (`sudo service postgresql start`, then
`ALTER USER postgres WITH PASSWORD 'webhawk123'; CREATE DATABASE webhawk;`
via `psql`), and set `DB_HOST=127.0.0.1` in your local `.env` for this.

Then, for any one service:
```bash
cd services/<service-name>       # e.g. services/users
mkdir -p build && cd build
cmake .. && make
cd ..
./build/<executable-name>
```
Run it from the **service's own folder** (not from `build/`), so
`config.json` and the relative path to the root `.env` resolve correctly.
Only run **one** service this way at a time - they all listen on port 8080,
so two running natively at once on the same machine will conflict.