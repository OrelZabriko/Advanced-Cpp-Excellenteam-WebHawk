# WebHawk - Advanced C++ Excellenteam Final Project

WebHawk is a security middleware platform: every incoming request is checked for
SQL injection, XSS, and rate-limit abuse before it's forwarded to the real backend it's protecting.

---
## Team

| Name | ID | Email |
|---|---|---|
| Benny Beer | 312556657 | bennybe@edu.jmc.ac.il |
| Nadav Ben Melech | 211728316 | nadavbenm@edu.jmc.ac.il |
| Orel Zabriko     | 211845458 | orelzab@edu.jmc.ac.il   |

---

## How a request flows
 
Every request that reaches the middleware goes through four stages, in order.
Any stage can end the request early; only a request that passes all four is
forwarded to the real backend.
 
```
  client
    │  X-API-Key: whk_live_...
    │  Authorization: Bearer <jwt>
    ▼
┌─────────────────────────────────────────────┐
│ middleware  (setDefaultHandler, catch-all)  │
└─────────────────────────────────────────────┘
    │
    │ 1. GET /backends/lookup?api_key=...      ──►  backend_registry
    │    Which backend does this key belong to,
    │    and is it currently active?
    │    ✗ unknown key → 404   ✗ paused → 403
    │
    │ 2. GET /validate                         ──►  users
    │    Is this JWT signed correctly, unexpired,
    │    and its session still un-revoked?
    │    ✗ missing / invalid → 401
    │
    │ 3. POST /analyze                         ──►  security_engine
    │    Does this request contain SQLi, XSS,
    │    or has this IP exceeded its rate limit?
    │    ✗ sqli / xss → 403   ✗ rate_limit → 429
    │
    │ 4. forward to target_url                 ──►  the real backend
    ▼
  the real backend's response, passed back verbatim
```
 
The middleware registers no routes of its own. It installs a single
`setDefaultHandler` (see `middleware/main.cc`), so *every* path and method that
reaches it goes through the pipeline above - it is a proxy, not an API.
 
---

## Services
 
| Compose service | Source folder | Host port | Role |
|---|---|---|---|
| `middleware` | `middleware/` | **8080** | The public entry point. All protected traffic. |
| `security_engine` | `services/security-engine/` | 8081 | SQLi / XSS / rate-limit detection. |
| `users` | `services/users/` | 8082 | Registration, login, JWT issue and revoke. |
| `backend_registry` | `services/backend_registry/` | 8083 | Backend registration and API key issuance. |
| `postgres` | - | 5432 | Shared database. |
 
Each service is an independent Drogon executable with its own `main.cc`,
`CMakeLists.txt`, and Dockerfile (`Dockerfile-security`, `Dockerfile-users`, and
so on). **All four listen internally on port 8080** - that's fine because each
runs in its own container with its own network namespace.
 
**Host port vs container port.** The `ports: "8081:8080"` entries above are
`host:container` mappings - they only open a door from your WSL shell into the
container. Container-to-container traffic does not go through the host, so the
middleware always calls the other services on **8080**, never on 8081/8082/8083
(see `middleware/clients/ServiceEndpoints.h`).
 
**A note on why the three internal services are published at all.** In the
intended production shape only `middleware` would publish a port - everything
else would be reachable only from inside the Docker network. The extra mappings
exist so each service can be tested in isolation during development, which
matters because a request that fails end-to-end otherwise has three possible
culprits and no way to tell them apart. Remove them for a real deployment.
 
**Service names use underscores in Compose, hyphens in folder paths.** Docker's
internal DNS resolves the **Compose service name**, so the middleware calls
`http://security_engine:8080` even though the source lives in
`services/security-engine/`. This is worth knowing before editing
`ServiceEndpoints.h` - a hyphen there will not resolve.
 
---

## Prerequisites
 
- Docker + Docker Compose
- Developed inside **WSL (Ubuntu)** - not native Windows - but everything below
  runs the same way once Docker is installed.
## Setup
 
### 1. Clone the repo (inside WSL)
 
```bash
cd ~
git clone git@github.com:OrelZabriko/Advanced-Cpp-Excellenteam-WebHawk.git
cd Advanced-Cpp-Excellenteam-WebHawk
```
 
### 2. Create your `.env` file
 
All secrets and per-environment settings live in a single `.env` at the repo root
- **not committed to git**. Copy the template:
```bash
cp .env.example .env
```
 
Then set a real `JWT_SECRET` - the users service refuses to start without one:
 
```bash
openssl rand -base64 32
```
 
Every variable is documented in the [Configuration](#configuration) section below.
 
### 3. Run everything
 
```bash
docker compose up --build
```
 
This builds and starts every service on one Docker network, and initialises
Postgres automatically from the `.sql` files in `db/`.
 
To reset completely - dropping all users, registrations, logs and rate-limit
counters:
 
```bash
docker compose down -v && docker compose up --build
```
 
The `-v` flag is what drops the Postgres volume. Without it, old rows survive
across restarts, which will make rate-limit tests behave unexpectedly.

---

## API reference
 
### middleware - `localhost:8080`
 
Accepts any path and any method. Two headers are required on every request.
 
| Header | Purpose |
|---|---|
| `X-API-Key` | Identifies which registered backend this request is for. |
| `Authorization: Bearer <jwt>` | Identifies the end user. Required with no exceptions. |
 
| Status | Meaning |
|---|---|
| `200` (or whatever the backend returns) | Allowed and forwarded. |
| `401` | Missing `X-API-Key`, missing `Authorization`, or invalid/revoked token. |
| `404` | The API key is not registered. |
| `403` | Blocked as `sqli`/`xss`, or the backend's protection is paused. |
| `429` | Blocked as `rate_limit`. |
| `500` | An internal service was unreachable or failed. |
 
A blocked response is deliberately generic - it names the `attack_type` but never
the specific rule that fired.
 
### backend_registry - `localhost:8083`
 
| Method | Path | Body | Returns |
|---|---|---|---|
| `POST` | `/backends` | `{service_name, target_url}` | `201` with the full registration **including `api_key`** |
| `GET` | `/backends/lookup?api_key=...` | - | `200` with `{found, service_name, target_url, active}` |
| `GET` | `/backends` | - | `200` with all registrations, **never including `api_key`** |
| `PUT` | `/backends/{id}` | `{service_name, target_url}` | `200`, or `404` if no such id |
| `PATCH` | `/backends/{id}/status` | `{active: true\|false}` | `200`, or `404` if no such id |
 
`GET /backends/lookup` returns `200` with `{"found": false}` for an unknown key -
not `404`. Per Contract B, "not found" is a normal business outcome for this
endpoint, not an HTTP error.
 
`PATCH .../status` is how a developer pauses protection without deleting the
registration. While paused, the middleware refuses requests for that backend
with `403`.
 
### users - `localhost:8082`
 
| Method | Path | Body / Header | Returns |
|---|---|---|---|
| `POST` | `/register` | `{email, password}` | `201`, or `409` if the email exists |
| `POST` | `/login` | `{email, password}` | `200` with `{token}`, or `401` |
| `POST` | `/logout` | `Authorization: Bearer <jwt>` | `200`, or `404` if already revoked |
| `GET` | `/validate` | `Authorization: Bearer <jwt>` | `200` with `{valid, user_id}`, or `401` |
 
Wrong password and unknown email both return the same `401` message. This is
deliberate - a different message for each would let anyone enumerate which email
addresses are registered.
 
`/validate` checks more than the JWT's own signature and expiry: it also confirms
the matching row in `user_sessions` is still `active`. That is what makes
`/logout` meaningful - a token can be invalidated before it naturally expires,
which a signature check alone could never do.
 
### security_engine - `localhost:8081`
 
| Method | Path | Returns |
|---|---|---|
| `POST` | `/analyze` | `200` allowed, `403` sqli/xss, `429` rate_limit, `400` malformed |
 
Request body (Contract A):
 
```json
{
  "endpoint": "/api/search",
  "method": "POST",
  "ip": "172.18.0.1",
  "headers": {},
  "query_params": {},
  "path_params": {},
  "body": {"q": "hello"}
}
```
 
`endpoint`, `method` and `ip` are required; the rest are scanned if present.
Every string value found anywhere in `headers`, `query_params`, `path_params`
and `body` is checked, at any nesting depth.
 
Response:
 
```json
{"allowed": true, "attack_type": null, "reason": null}
```
 
`attack_type` and `reason` are **always present** - as explicit `null` on a clean
request, never omitted. The middleware relies on that guarantee, so a missing key
and an explicit `null` are not interchangeable here.
 
---

## Security notes
 
- **Passwords are hashed with bcrypt** (`services/users/utils/HashUtils.cc`),
  not a fast hash like SHA-256. bcrypt's built-in salting and deliberately slow
  cost factor are what make hashes resistant to brute-force and rainbow-table
  attacks. There's no official Ubuntu package, so it's built from source -
  handled automatically in `Dockerfile-users`.
- **JWTs use `cpp-jwt`**, also built from source for the same reason, also
  handled in `Dockerfile-users`.
- **All SQL uses parameterised prepared statements** (`$1`, `$2`, ...). No query
  in this project is built by string concatenation - which matters more than
  usual here, given that the whole point of the product is blocking SQL
  injection.
- **API keys are shown exactly once**, at creation time (`POST /backends`).
  `GET /backends` never returns `api_key` for any registration - otherwise
  anyone with list access could read out every backend's live credential.
- **The middleware identifies the target backend via an `X-API-Key` header.**
  This is a judgment call, not a locked-in team decision: the API Contracts doc
  defines the *lookup* (Contract B: given an api_key, find the target) but not
  how that key travels on the request.
- **Every internal HTTP call has an explicit 5-second timeout** (see
  `ProxyService.cc`). `HttpClient::sendRequest`'s third argument is the timeout
  in seconds, and `0` - the default when omitted - means "wait forever". Without
  an explicit value, one hung service or one slow real backend would tie up the
  request indefinitely instead of failing fast with a 500.
- **Internal error details never reach the client.** A failed internal call is
  logged server-side with its context ("security-engine unreachable"), but the
  client always receives the same generic 500. An earlier version put the context
  in the response body, which meant anyone who could trigger a 500 could map the
  internal service topology.
- **Every issued JWT carries a random `jti` claim.** Without it the payload
  would be only `user_id` and `exp`, and `std::time` has one-second
  granularity - so two logins by the same user in the same second would
  produce a byte-identical token, colliding with the `UNIQUE` constraint on
  `user_sessions.token_id` and turning a valid login into a 500. `jti`
  ("JWT ID", RFC 7519 4.1.7) exists for exactly this.
- **Every service installs global error handlers** (`ErrorHandlers::installAll()`
  in each `main.cc`, from `services/shared/ErrorHandlers.h`). These guarantee
  that every response carries a JSON body - including the 404/405 Drogon raises
  before routing, and any exception a controller did not anticipate. Exception
  text is logged server-side and never returned to the client, since `e.what()`
  on a DB or JSON error routinely contains table names or the raw query.
  Per-controller validation still handles known bad input; this is the net
  underneath it, not a replacement.
- **The users service refuses to start without `JWT_SECRET`** (see
  `AuthConfig::JWT_SECRET()` and `main.cc`) - it does not fall back to a
  guessable default. If you see `[users] fatal startup error: JWT_SECRET is not
  set` in `docker compose logs users`, set one:
  - **Generate it (recommended):** `openssl rand -base64 32` - 32 bytes of real
    randomness, the minimum recommended for HS256.
  - **Type it yourself** only if `openssl` isn't available: at least 40-50 mixed
    characters, not a word or phrase, not reused anywhere. A human-typed string
    is never as strong as a generated one - treat this as a fallback.
- **Same fail-fast applies to `JWT_ALGORITHM`** - only `HS256`, `HS384` and
  `HS512` are supported (`AuthConfig::algorithmEnum()`). Anything else, including
  asymmetric algorithms like `RS256`, makes users refuse to start. Asymmetric
  algorithms need a public/private key pair rather than the single shared secret
  this project uses, so supporting them would require a different config shape
  entirely - not just another enum branch.

---

## Configuration
 
Every variable, from `.env.example`:
 
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
 
Config is split by ownership, on one shared loader:
 
| File | Owns | Used by |
|---|---|---|
| `services/shared/EnvLoader.h` | reads `.env` once per process | all three below |
| `services/shared/DbConfig.h` | `DB_*` | every service that talks to Postgres |
| `services/users/utils/AuthConfig.h` | `JWT_*` | users only |
| `services/security-engine/utils/SecurityConfig.h` | `RATE_LIMIT_*` | security-engine only |
 
Each service's `main.cc` builds its DB connection from `DbConfig::HOST()` and
friends in code, so the password never sits in a committed file. `config.json`
now only defines the port the service listens on.
 
**`DB_HOST=postgres`** because the project runs under Docker Compose by default -
`postgres` is the Compose service name, resolved by Docker's internal DNS.
Override it to `127.0.0.1` only if you're running a service natively for
debugging (see below).
 
**`.env` is read by two independent mechanisms.** First, `EnvLoader.h`, used by
each Drogon service at runtime. Second, **Docker Compose itself**, which
substitutes `${VAR}` anywhere in `docker-compose.yml` from a file literally named
`.env` at the repo root - a built-in Compose feature, not something this project
added. That's how `postgres`'s own `POSTGRES_USER`/`POSTGRES_PASSWORD`/
`POSTGRES_DB` avoid being hardcoded: they read `${DB_USER}`/`${DB_PASSWORD}`/
`${DB_NAME}` from the same file every service already reads.
 
**`.env` syntax rule:** each line must be `KEY=VALUE` only - no spaces around
`=`, no trailing comment on a value line. Only a line *starting* with `#` is a
comment (see `EnvLoader.h`). `DB_HOST=postgres # docker` would parse as the
literal value `postgres # docker` and break the connection.
 
**`.dockerignore`** (repo root) exists so `.env` never gets baked into an image.
`.gitignore` only controls what goes into *git* - it has no effect on what
`COPY . /app` puts inside an image, so without `.dockerignore` the real secrets
would end up in the built image's layers.
 
**Line endings:** `.gitattributes` forces `eol=lf` on all text files. This repo
previously had a CRLF/LF mix, which caused a real bug - a trailing `\r` ending up
inside `DB_HOST`'s value when `.env` was saved with Windows line endings.
`EnvLoader.h` now strips it defensively, but don't rely on that; keep files LF.
 
**`.vscode/c_cpp_properties.json` is committed** (the only file in `.vscode/`
that is) so IntelliSense works the same for everyone. It points at each service's
`compile_commands.json`, generated by CMake (`CMAKE_EXPORT_COMPILE_COMMANDS ON`,
already set) the first time you run `cmake ..` in that service's `build/` folder.
Build each service once, then reload VS Code and pick the matching configuration
(`Ctrl+Shift+P` → "C/C++: Select a Configuration").
 
### Why `RATE_LIMIT_WINDOW_SECS` stays in seconds
 
The window is applied directly in seconds all the way through
`SecurityConfig` → `SecurityService` → `SecurityRepository` → SQL
(`make_interval(secs => ...)`). No conversion to minutes happens anywhere.
 
This was a real security bug, not a precision nitpick. An earlier version
converted to whole minutes first with integer division, because
`make_interval`'s `mins` parameter only accepts whole integers - so the rounding
was unavoidable as long as the window was expressed in minutes at all:
 
- `RATE_LIMIT_WINDOW_SECS=90` → `90 / 60 = 1` minute → real window silently
  became **60 seconds**. The limit was *weaker* than configured; an attacker
  could reset it a third sooner than intended.
- `RATE_LIMIT_WINDOW_SECS=30` → `30 / 60 = 0`, clamped to `1` → real window
  silently became **60 seconds**. This time *stricter*; legitimate users stayed
  blocked twice as long as intended.
Either way, a variable named `..._SECS` claimed one thing and enforced another,
with no way to tell from reading `.env`. Switching the whole chain to
`make_interval`'s `secs` parameter removes the conversion, so the configured
value and the actual behaviour can't drift apart.
 
---

## Database
 
Schema lives in `db/` as plain `.sql` files, loaded automatically by the
`postgres` container on first start (via `docker-entrypoint-initdb.d`).
 
| Table | Owner | Purpose |
|---|---|---|
| `users` | users | One row per account. `password_hash` holds a bcrypt hash, which embeds its own salt - no separate salt column needed. |
| `user_sessions` | users | One row per login. Lets a JWT be revoked before it expires. |
| `backend_registration` | backend_registry | One row per protected backend. `api_key` is `UNIQUE`, which also gives lookups their index for free. |
| `security_logs` | security_engine | Audit trail of every analysed request, clean or blocked. |
| `rate_limit` | security_engine | Running request counter per IP per endpoint. `UNIQUE(ip, endpoint)` means one row per pair, updated in place. |
 
Because the schema files only run on **first** start, editing a `.sql` file has
no effect on an existing volume. Use `docker compose down -v` to force a reload.
 
 
## Debugging a single service natively (optional)
 
Only needed to build or run one service directly on your machine, outside Docker,
for faster iteration - not the normal way to use the project.
 
Install Drogon (course install script; confirm with
`ls /usr/local/include/drogon/drogon.h`), then the two libraries with no official
Ubuntu package:
 
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
 
Start Postgres yourself (`sudo service postgresql start`, then via `psql`:
`ALTER USER postgres WITH PASSWORD '<your DB_PASSWORD>'; CREATE DATABASE <your DB_NAME>;`)
and set `DB_HOST=127.0.0.1` in your local `.env`.
 
Then, for any one service:
 
```bash
cd services/<service-name>       # e.g. services/users
mkdir -p build && cd build
cmake .. && make
cd ..
./build/<executable-name>
```
 
Run it from the **service's own folder**, not from `build/`, so `config.json` and the relative path to 
the root `.env` resolve correctly. Only run **one** service this way at a time - they all listen on 
8080 and will conflict.
 
This same `cmake ..` generates the `compile_commands.json` that `.vscode/c_cpp_properties.json` points at, so 
it's worth doing once per service even if you never run them natively, just to fix editor include errors.

---

## Postman

`postman/WebHawk_Full_Collection.json` covers the whole project - all four services, in run order: `backend_registry` (registration and lookup), `users` (registration, login, JWT validation and revocation), `security_engine` (`/analyze` in isolation), and finally the `middleware` pipeline end to end.

Import it into Postman and run the folders in order. Two things depend on that order: the `api_key` from the first `backend_registry` request and the `token` from the `users` login are reused by every later request, and the `users` folder logs out at the end - so log in again before running the `middleware` folder.

Worked examples of every request and its expected response are in the [Postman Examples](#postman-examples) section below.


## Postman Examples

### backend_registry Tests
#### Test 1.1
##### Request
- Method: POST 
- URL: ``` http://localhost:8083/backends ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "service_name": "google-api",
      "target_url": "http://demo-backend:8080"
    }
  ```
- Save the api_key you will get in the result!

##### Response
- status: ``` 201 Created ```
- 
  ```json
  {
      "active": true,
      "api_key": "whk_live_38cff3a620f6eb47bc7ee2b0d57f35fc",
      "created_at": "2026-07-22 11:56:43.114419+00",
      "id": 1,
      "service_name": "google-api",
      "target_url": "http://demo-backend:8080"
  }
  ```


#### Test 1.2
##### Request
- Method: GET
- URL: ``` http://localhost:8083/backends/lookup?api_key={{api_key}} ```

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "active": true,
      "found": true,
      "service_name": "google-api",
      "target_url": "http://demo-backend:8080"
  }
  ```


#### Test 1.3
##### Request
- Method: GET
- URL: ``` http://localhost:8083/backends/lookup?api_key=whk_live_doesnotexist ```

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "found": false
  }
  ```


#### Test 1.4
##### Request
- Method: GET
- URL: ``` http://localhost:8083/backends ```

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "backends": [
          {
              "active": true,
              "created_at": "2026-07-22 11:56:43.114419+00",
              "id": 1,
              "service_name": "google-api",
              "target_url": "http://demo-backend:8080"
          },
          {
              "active": true,
              "created_at": "2026-07-22 12:11:36.029519+00",
              "id": 2,
              "service_name": "google-api",
              "target_url": "http://demo-backend:8080"
          }
      ]
  }
  ```


#### Test 1.5
##### Request
- Method: PUT
- URL: ``` http://localhost:8083/backends/1 ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "service_name": "google-api-v2",
      "target_url": "http://demo-backend:8080"
    }
  ```

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "id": 1,
      "message": "Backend updated successfully",
      "service_name": "google-api-v2",
      "target_url": "http://demo-backend:8080"
  }
  ```


#### Test 1.6
##### Request
- Method: POST
- URL: ``` http://localhost:8083/backends ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "service_name": "broken"
    }
  ```

##### Response
- status: ``` 400 Bad Request ```
- 
  ```json
  {
      "error": "Missing required field(s): target_url"
  }
  ```


#### Test 1.7
##### Request
- Method: POST
- URL: ``` http://localhost:8083/backends ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "service_name": "bad",
      "target_url": "demo-backend:8080"
    }
  ```

##### Response
- status: ``` 400 Bad Request ```
- 
  ```json
  {
      "error": "target_url must start with http:// or https://"
  }
  ```


#### Test 1.8
##### Request
- Method: PUT
- URL: ``` http://localhost:8083/backends/9999 ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "service_name": "x",
      "target_url": "http://x:8080"
    }
  ```

##### Response
- status: ``` 404 Not Found ```
- 
  ```json
  {
      "error": "Backend registration not found"
  }
  ```


### users Tests
#### Test 2.1
##### Request
- Method: POST
- URL: ``` http://localhost:8082/register ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "email": "test@test.com",
      "password": "Secret123!"
    }
  ```

##### Response
- status: ``` 201 Created ```
- 
  ```json
  {
      "message": "User registered successfully"
  }
  ```

#### Test 2.2
##### Request
- Method: POST
- URL: ``` http://localhost:8082/register ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "email": "test@test.com",
      "password": "Secret123!"
    }
  ```

##### Response
- status: ``` 409 Conflict ```
- 
  ```json
  {
      "error": "Email already exists"
  }
  ```


#### Test 2.3
##### Request
- Method: POST
- URL: ``` http://localhost:8082/login ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body: 
  ```
    {
      "email": "test@test.com",
      "password": "Secret123!"
    }
  ```
- Save the token you will get in the result!

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "message": "Login successful",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3ODQ4MTIzNTAsImp0aSI6IjNhNzBkNDcxMGFkYTExYTkiLCJ1c2VyX2lkIjoiMSJ9.stee71tumpCmaBuB_PSGx6cyH-GS4EdtzKpYUp3bh-Y"
  }
  ```


#### Test 2.4
##### Request
- Method: POST
- URL: ``` http://localhost:8082/login ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "email": "test@test.com",
      "password": "wrong"
    }
  ```

##### Response
- status: ``` 401 Unauthorized ```
- 
  ```json
  {
      "error": "Invalid email or password"
  }
  ```


#### Test 2.5
##### Request
- Method: GET
- URL: ``` http://localhost:8082/validate ```
- Headers:   
    KEY: ``` Authorization ```  
    VALUE: ``` Bearer {{token}} ``` 

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "user_id": 1,
      "valid": true
  }
  ```


#### Test 2.6
##### Request
- Method: GET
- URL: ``` http://localhost:8082/validate ```

##### Response
- status: ``` 401 Unauthorized ```
- 
  ```json
  {
      "reason": "Missing or invalid Authorization header",
      "valid": false
  }
  ```


#### Test 2.7
##### Request
- Method: POST
- URL: ``` http://localhost:8082/logout ```
- Headers:   
    KEY: ``` Authorization ```  
    VALUE: ``` Bearer {{token}} ``` 

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "message": "Logged out successfully"
  }
  ```


#### Test 2.8
##### Request
- Method: GET
- URL: ``` http://localhost:8082/validate ```
- Headers:   
    KEY: ``` Authorization ```  
    VALUE: ``` Bearer {{token}} ``` 

##### Response
- status: ``` 401 Unauthorized ```
- 
  ```json
  {
      "reason": "Token revoked or expired",
      "valid": false
  }
  ```


### security_engine Tests
#### Test 3.1
##### Request
- Method: POST
- URL: ``` http://localhost:8081/analyze ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "endpoint": "/api/clean-test",
      "method": "POST",
      "ip": "10.0.0.1",
      "headers": {"User-Agent": "curl"},
      "query_params": {},
      "path_params": {},
      "body": {"username": "orel"}
    }
  ```

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "allowed": true,
      "attack_type": null,
      "reason": null
  }
  ```

#### Test 3.2
##### Request
- Method: POST
- URL: ``` http://localhost:8081/analyze ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "endpoint": "/api/sqli-test",
      "method": "POST",
      "ip": "10.0.0.2",
      "headers": {},
      "query_params": {},
      "path_params": {},
      "body": {"username": "admin' OR 1=1 --"}
    }
  ```

##### Response
- status: ``` 403 Forbidden ```
- 
  ```json
  {
      "allowed": false,
      "attack_type": "sqli",
      "reason": "SQL injection pattern detected"
  }
  ```


#### Test 3.3
##### Request
- Method: POST
- URL: ``` http://localhost:8081/analyze ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "endpoint": "/api/xss-test",
      "method": "POST",
      "ip": "10.0.0.3",
      "headers": {},
      "query_params": {"q": "<script>alert(1)</script>"},
      "path_params": {},
      "body": {}
    }
  ```

##### Response
- status: ``` 403 Forbidden ```
- 
  ```json
  {
      "allowed": false,
      "attack_type": "xss",
      "reason": "XSS pattern detected"
  }
  ```


#### Test 3.4
##### Request
- Method: POST
- URL: ``` http://localhost:8081/analyze ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "endpoint": "/api/rate-test",
      "method": "GET",
      "ip": "10.0.0.99",
      "headers": {},
      "query_params": {},
      "path_params": {},
      "body": {}
    }
  ```

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "allowed": true,
      "attack_type": null,
      "reason": null
  }
  ```


#### Test 3.5
##### Request
- Method: POST
- URL: ``` http://localhost:8081/analyze ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "method": "GET"
    }
  ```

##### Response
- status: ``` 400 Bad Request ```
- 
  ```json
  {
      "error": "Missing required fields: endpoint, method, ip"
  }
  ```



### middleware Tests
#### Test 4.1
##### Request
- Method: GET
- URL: ``` http://localhost:8080/api/anything ```

##### Response
- status: ``` 401 Unauthorized ```
- 
  ```json
  {
      "error": "Missing X-API-Key header"
  }
  ```


#### Test 4.2
##### Request
- Method: GET
- URL: ``` http://localhost:8080/api/anything ```
- Headers:   
    KEY: ``` X-API-Key ```  
    VALUE: ``` whk_live_fake123 ```  

##### Response
- status: ``` 403 Forbidden ```
- 
  ```json
  {
      "error": "Unknown API key"
  }
  ```


#### Test 4.3
##### Request
- Method: GET
- URL: ``` http://localhost:8080/api/anything ```
- Headers:   
    KEY: ``` X-API-Key ```  
    VALUE: ``` {{api_key}} ``` 

##### Response
- status: ``` 401 Unauthorized ```
- 
  ```json
  {
      "error": "Authorization header required"
  }
  ```


#### Test 4.4
##### Request
- Method: GET
- URL: ``` http://localhost:8080/api/anything ```
- Headers:   
    KEY-1: ``` X-API-Key ```  
    VALUE-1: ``` {{api_key}} ```
    KEY-2: ``` Authorization ```  
    VALUE-2: ``` Bearer garbage.token.here ```

##### Response
- status: ``` 401 Unauthorized ```
- 
  ```json
  {
      "error": "Invalid or expired token"
  }
  ```


#### Test 4.5
##### Request
- Method: POST
- URL: ``` http://localhost:8080/api/users/profile ```
- Headers:   
    KEY-1: ``` X-API-Key ```  
    VALUE-1: ``` {{api_key}} ```
    KEY-2: ``` Authorization ```  
    VALUE-2: ``` Bearer {{token}} ```
    KEY-3: ``` Content-Type ```  
    VALUE-3: ``` application/json ```
- Body:  
  ```
    {
      "name": "Oren",
      "city": "Jerusalem"
    }
  ```

##### Response
- status: ``` 500 Internal Server Error ```
- 
  ```json
  {
      "error": "Internal server error"
  }
  ```


#### Test 4.6
##### Request
- Method: POST
- URL: ``` http://localhost:8080/api/users/search ```
- Headers:   
    KEY-1: ``` X-API-Key ```  
    VALUE-1: ``` {{api_key}} ```
    KEY-2: ``` Authorization ```  
    VALUE-2: ``` Bearer {{token}} ```
    KEY-3: ``` Content-Type ```  
    VALUE-3: ``` application/json ```  
- Body:  
  ```
    {
      "query": "admin' OR 1=1 --"
    }
  ```

##### Response
- status: ``` 403 Forbidden ```
- 
  ```json
  {
      "attack_type": "sqli",
      "error": "Request blocked"
  }
  ```


#### Test 4.7
##### Request
- Method: GET
- URL: ``` http://localhost:8080/api/comments?text=<script>alert(1)</script> ```
- Headers:   
    KEY-1: ``` X-API-Key ```  
    VALUE-1: ``` {{api_key}} ```
    KEY-2: ``` Authorization ```  
    VALUE-2: ``` Bearer {{token}} ``` 

##### Response
- status: ``` 403 Forbidden ```
- 
  ```json
  {
      "attack_type": "xss",
      "error": "Request blocked"
  }
  ```


#### Test 4.8
##### Request
- Method: GET
- URL: ``` http://localhost:8080/api/ratelimit-e2e ```
- Headers:   
    KEY-1: ``` X-API-Key ```  
    VALUE-1: ``` {{api_key}} ```
    KEY-2: ``` Authorization ```  
    VALUE-2: ``` Bearer {{token}} ``` 

##### Response
- status: ``` 429 Too Many Requests ```
- 
  ```json
  {
      "attack_type": "rate_limit",
      "error": "Request blocked"
  }
  ```


#### Test 4.9.1
##### Request
- Method: PATCH
- URL: ``` http://localhost:8083/backends/1/status ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "active": false
    }
  ```

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "active": false,
      "id": 1,
      "message": "Status updated successfully"
  }
  ```


#### Test 4.9.2
##### Request
- Method: GET
- URL: ``` http://localhost:8080/api/anything ```
- Headers:   
    KEY-1: ``` X-API-Key ```  
    VALUE-1: ``` {{api_key}} ```
    KEY-2: ``` Authorization ```  
    VALUE-2: ``` Bearer {{token}} ``` 
- Body:  
  ```
    
  ```

##### Response
- status: ``` 403 Forbidden ```
- 
  ```json
  {
      "error": "This backend's protection is currently paused"
  }
  ```


#### Test 4.9.3
##### Request
- Method: PATCH
- URL: ``` http://localhost:8083/backends/1/status ```
- Headers:   
    KEY: ``` Content-Type ```  
    VALUE: ``` application/json ```  
- Body:  
  ```
    {
      "active": true
    }
  ```

##### Response
- status: ``` 200 OK ```
- 
  ```json
  {
      "active": true,
      "id": 1,
      "message": "Status updated successfully"
  }
  ```