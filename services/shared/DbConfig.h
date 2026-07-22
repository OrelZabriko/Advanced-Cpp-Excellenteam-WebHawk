#pragma once

#include "EnvLoader.h"
#include <cstdlib>
#include <string>

// Database connection settings, read from the repo-root .env.
// Shared by every service that talks to Postgres: users, security-engine,
// backend-registry. Each getter falls back to a sane default if the
// corresponding .env variable isn't set.
class DbConfig 
{
public:
    // Defaults to "postgres" (the Docker Compose service name for Postgres),
    // matching the .env.example default - i.e. "assume we're running in
    // Docker unless told otherwise". If you ever run a service natively
    // (outside Docker, straight on WSL) for debugging, override DB_HOST to
    // 127.0.0.1 in your local .env for that session.
    static std::string HOST() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("DB_HOST");
        return val ? std::string(val) : "postgres";
    }

    static int PORT() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("DB_PORT");
        return val ? std::stoi(val) : 5432;
    }

    static std::string USER() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("DB_USER");
        return val ? std::string(val) : "postgres";
    }

    // No hardcoded default password on purpose - if DB_PASSWORD is missing,
    // this returns an empty string rather than a guessable fallback.
    static std::string PASSWORD() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("DB_PASSWORD");
        return val ? std::string(val) : "";
    }

    static std::string NAME() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("DB_NAME");
        return val ? std::string(val) : "webhawk";
    }
};