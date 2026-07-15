# Users Service

Handles registration, login, JWT issuing, sessions, and logout.

For setup, build, run instructions, and the `.env` file - see the
[root README](../../README.md). This service listens on port 8080 and reads
its DB config from `services/shared/DbConfig.h` and its JWT config from
`services/users/utils/AuthConfig.h`, both backed by the repo-root `.env`.