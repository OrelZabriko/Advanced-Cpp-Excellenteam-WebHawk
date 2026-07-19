# WebHawk - Advanced C++ Excellenteam Final Project

WebHawk is a security middleware platform: every incoming request is checked for
SQL injection, XSS, and rate-limit abuse before it's forwarded to the real backend it's protecting.


## Team

| Name | ID | Email |
|---|---|---|
| Benny Beer | 312556657 | bennybe@edu.jmc.ac.il |
| Nadav Ben Melech | 211728316 | nadavbenm@edu.jmc.ac.il |
| Orel Zabriko     | 211845458 | orelzab@edu.jmc.ac.il   |


## Services
 
| Compose service | Source folder | Host port | Role |
|---|---|---|---|
| `middleware` | `middleware/` | **8080** | The public entry point. All protected traffic. |
| `security_engine` | `services/security-engine/` | 8081 | SQLi / XSS / rate-limit detection. |
| `users` | `services/users/` | 8082 | Registration, login, JWT issue and revoke. |
| `backend_registry` | `services/backend_registry/` | 8083 | Backend registration and API key issuance. |
| `postgres` | - | 5432 | Shared database. |

Each service is an independent Drogon executable with its own `main.cc`,
`CMakeLists.txt`, and Dockerfile (`Dockerfile-security` for security-engine,
`Dockerfile-users` for users, and so on per service), and all listen on the
same internal port (8080) - that's fine because each runs in its own Docker
container with its own isolated network namespace. Only the middleware's
container publishes its port to the host; every other service is reachable
only from inside the Docker network, by service name (e.g.
`http://security-engine:8080/analyze`).


## Security notes

- **Passwords are hashed with bcrypt** (`services/users/utils/HashUtils.cc`), per the project spec - not 
  a plain fast hash like SHA-256, since bcrypt's built-in salting and deliberately slow cost factor are 
  what make password hashes resistant to brute-force/rainbow-table attacks. There's no official Ubuntu 
  package for it, so it's built from source - already handled automatically inside `Dockerfile-users`; only 
  needed manually if running the users service natively (see the bottom of this file).
- **JWTs use `cpp-jwt`**, also built from source for the same reason (no official Ubuntu package) - also 
  handled automatically in `Dockerfile-users`.
- Per Contract A in the API Contracts doc, `POST /analyze`'s response always includes `attack_type` and 
  `reason` - as explicit `null` on a clean/allowed request, not omitted - so callers can rely on both 
  fields always being present.
- **`backend-registry`'s API keys are shown exactly once** - at creation time (`POST /backends`). 
  `GET /backends` (the listing endpoint) never returns `api_key` for any registration, the same way a 
  real secret/API key is normally handled - otherwise anyone with list access could read out every
  backend's live credential.
- **The middleware identifies which registered backend to use via an `X-API-Key` header** on 
  every request it receives. This is a judgment call, not a locked-in team decision - the API 
  Contracts doc defines the *lookup* (Contract B: given an api_key, find the target) but not 
  how that key travels on the request. 
- **Every internal HTTP call the middleware makes (lookup, /validate, /analyze, and the real
  backend) has an explicit timeout** (5s by default - see `ProxyService.cc`). Without this, a 
  single slow or hung internal service - or a slow real backend the client doesn't
  control - would tie up the request indefinitely instead of failing fast with a 500. 
  `HttpClient::sendRequest`'s third argument is the timeout in seconds; `0` (the default if 
  omitted) means "no timeout", which is why this has to be set explicitly on every call.
- **The users service refuses to start if `JWT_SECRET` is missing from `.env`** (see `AuthConfig::JWT_SECRET()` 
  and `main.cc`) - it does not fall back to a guessable default. Every token this service signs is only as safe 
  as this secret. If you see `[users] fatal startup error: JWT_SECRET is not set` in `docker compose logs users`, copy
  `.env.example` to `.env` and set a real secret using one of:
  - **Generate it (recommended)** - on Linux/WSL/macOS:
    `openssl rand -base64 32`. This gives 32 bytes of real randomness, the minimum recommended key size for HS256.
  - **Type it yourself** - only if `openssl` isn't available. Bang out at least 40-50 random characters (mix of 
    upper/lower case, digits, symbols) - not a word, phrase, or anything you'd reuse elsewhere. A human-typed string 
    is *never* as strong as a generated one (people are bad at being random), so treat this as a fallback, not a preference.
- **Same fail-fast applies to `JWT_ALGORITHM`** - only `HS256`, `HS384`, and `HS512` are supported (see 
  `AuthConfig::algorithmEnum()`). Anything else (a typo, or an asymmetric algorithm like `RS256`/`ES256`) makes 
  `users` refuse to start with `[users] fatal startup error: Unsupported JWT_ALGORITHM: <value>`. Asymmetric 
  algorithms aren't supported because this project signs and verifies with a single shared secret, not a 
  public/private key pair - supporting them would need a different config shape entirely, not just this value.


## Prerequisites

- Docker + Docker Compose
- This project is developed inside **WSL (Ubuntu)** - not native Windows -
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
config) live in a single `.env` file at the repo root - **not committed to git**.
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
  - `services/shared/EnvLoader.h` - reads `.env` once (used by all three below)
  - `services/shared/DbConfig.h` - `DB_*`, shared by every service that talks to Postgres
  - `services/users/utils/AuthConfig.h` - `JWT_*`, used only by users
  - `services/security-engine/utils/SecurityConfig.h` - `RATE_LIMIT_*`, used only by security-engine
- Each service's `main.cc` builds its DB connection from `DbConfig::HOST()` etc.
  in code; `config.json` only defines the port it listens on.
- **`.env` is read by two separate mechanisms, not one:** (1) `services/shared/EnvLoader.h`,
  used by each Drogon service at runtime (`DbConfig::HOST()` etc.), and (2) **Docker
  Compose itself**, which automatically substitutes `${VAR}` anywhere in
  `docker-compose.yml` from a file literally named `.env` at the repo root - this
  is a built-in Compose feature, not something this project added. That's how
  `postgres`'s own `POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB` avoid being
  hardcoded in `docker-compose.yml`: they're `${DB_USER}`/`${DB_PASSWORD}`/`${DB_NAME}`,
  resolved from the same `.env` every Drogon service already reads.
- **`.env` syntax rule**: each line must be `KEY=VALUE` only - no spaces around
  `=`, and no trailing comment on a value line. Only a line that starts with
  `#` is treated as a comment (see `EnvLoader.h`); `DB_HOST=postgres # docker`
  would be parsed as the literal value `postgres # docker` and break the
  connection.
- **`.dockerignore`** (repo root) exists so `.env` never gets baked into a
  Docker image. `.gitignore` only controls what goes into *git* - it has no
  effect on what `COPY . /app` puts inside an image, so without `.dockerignore`
  the real secrets in `.env` would end up inside the built image's layers.
- **`RATE_LIMIT_WINDOW_SECS` is applied directly in seconds**, all the way
  through `SecurityConfig` → `SecurityService` → `SecurityRepository` → SQL
  (`make_interval(secs => ...)`). No conversion to minutes happens anywhere,
  so any window size works precisely - not just whole-minute values.

  **Why this used to be a real security bug, not just a precision nitpick:**
  an earlier version converted the seconds value to whole minutes first,
  using integer division (`seconds / 60`), before handing it to
  `make_interval`. PostgreSQL's `make_interval` only accepts a whole integer
  for its `mins` parameter (only its `secs` parameter supports fractions),
  so this rounding was unavoidable as long as the window was expressed in
  minutes at all. Two concrete failure cases:
  - `RATE_LIMIT_WINDOW_SECS=90` (a 90-second window) → `90 / 60 = 1` minute
    → the real window silently became **60 seconds**. The rate limit was
    *weaker* than configured - an attacker could "reset" it a third sooner
    than intended.
  - `RATE_LIMIT_WINDOW_SECS=30` (a 30-second window) → `30 / 60 = 0` minutes,
    clamped up to `1` → the real window silently became **60 seconds**. This
    time the rate limit was *stricter* than configured - legitimate users
    could stay blocked twice as long as intended.

  Both directions matched the exact same `.env` variable name
  (`RATE_LIMIT_WINDOW_SECS`) claiming to be in seconds while actually
  behaving differently underneath - whoever tunes this value for a security
  requirement (e.g. "block for 90s after abuse") would have no way to know,
  from reading `.env` alone, that the real system enforced something else.
  Switching the whole chain to seconds (using `make_interval`'s `secs`
  parameter, the one that natively supports fractional/precise values)
  removes the conversion entirely, so the configured value and the actual
  behavior can never drift apart.
- **Line endings**: `.gitattributes` forces `eol=lf` on all text files. This
  repo previously had a CRLF/LF mix between `services/users` and
  `services/security-engine`, which was also the root cause of a real bug -
  a trailing `\r` ending up inside `DB_HOST`'s value when `.env` was saved
  with Windows line endings (`EnvLoader.h` now strips it defensively too,
  but don't rely on that - keep files LF).
- **`.vscode/c_cpp_properties.json` is committed** (the only file inside
  `.vscode/` that is - see `.gitignore`) so IntelliSense works the same for
  everyone. It points at each service's `compile_commands.json`, which CMake
  generates automatically (`CMAKE_EXPORT_COMPILE_COMMANDS ON`, already set in
  both `CMakeLists.txt`) the first time you run `cmake ..` in that service's
  `build/` folder - so build each service at least once, then reload VS Code
  and pick the matching configuration (bottom-right of the window, or
  `Ctrl+Shift+P` → "C/C++: Select a Configuration") for whichever service
  you're editing.


### 3. Run everything

```bash
docker compose up --build
```
This builds and starts every service as its own container on one Docker
network, and initializes Postgres automatically from the `.sql` files in `db/`.

**Only the middleware is reachable from outside Docker** (`localhost:8080`).
`users`, `security-engine`, and `backend-registry` have no external port at
all - there's no meaningful way to call them directly from outside Docker,
by design. End-to-end testing happens by hitting `localhost:8080` and
letting the middleware route the request through the rest of the system.

`middleware` and `services/backend-registry` are newly added and, unlike
`users`/`security-engine`, have not yet been verified against a real build -
expect (and report back) compiler errors on the first `docker compose up --build`
that includes them, the same way `users` needed a few rounds of fixes
(`bcrypt`, `cpp-jwt`) before it built cleanly.


## Database

Schema lives in `db/` as plain `.sql` files, loaded automatically by the
`postgres` container on first start (via `docker-entrypoint-initdb.d`).


## Debugging a single service natively (optional)

Only needed if you want to build/run one service directly on your machine,
outside Docker, for faster debugging - not the normal way to use the project.

Install locally: Drogon (course install script; confirm with
`ls /usr/local/include/drogon/drogon.h`), and two libraries with no official
Ubuntu package - build both from source:
```bash
# libbcrypt (password hashing)
git clone https://github.com/trusch/libbcrypt
cd libbcrypt && mkdir build && cd build
cmake .. && make
sudo make install && sudo ldconfig
cd ../..

# cpp-jwt (JWT signing/verification) - needs libssl-dev, nlohmann-json3-dev,
# and libgtest-dev (its default build also compiles its own test suite)
sudo apt-get install -y libssl-dev nlohmann-json3-dev libgtest-dev
git clone https://github.com/arun11299/cpp-jwt
cd cpp-jwt && mkdir build && cd build
cmake .. && sudo make install
cd ../..
```
Start Postgres yourself (`sudo service postgresql start`, then
`ALTER USER postgres WITH PASSWORD '<your DB_PASSWORD from .env>'; CREATE DATABASE <your DB_NAME from .env>;`
via `psql`), and set `DB_HOST=127.0.0.1` in your local `.env` for this.

Then, for any one service:
```bash
cd services/<service-name>       # e.g. services/users
mkdir -p build && cd build
cmake .. && make
cd ..
./build/<executable-name>
```
Run it from the **service's own folder** (not from `build/`), so `config.json` and the relative path to the root `.env` resolve correctly. Only run **one** service this way at a time - they all listen on port 8080, so two running natively at once on the same machine will conflict.

This same `cmake ..` also generates `compile_commands.json` in that service's `build/` folder, which is what `.vscode/c_cpp_properties.json` points at for IntelliSense (see above) - so this step is worth doing even if you don't plan to actually run the service natively, just to fix editor include errors.


## Postman

Test collections live in `postman/`. `webhawk_security_engine.postman_collection.json` documents the **intermediate testing** done directly against security-engine on port 8081, back when the middleware didn't exist yet and the service was reachable on its own - kept as-is, as a record of that stage. A separate, final collection - testing the whole system end-to-end through the middleware (`localhost:8080`, with an `X-API-Key` header identifying which registered backend to use - see Security notes above) - will be added once that flow is verified working.


## Postman Examples

<!-- Fill in with real request/response examples once the middleware is verified end-to-end. -->

### Request

```

```

### Response

```

```