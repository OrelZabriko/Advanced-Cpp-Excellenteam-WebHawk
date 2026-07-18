#pragma once

#include "../../shared/EnvLoader.h"
#include <cstdlib>
#include <string>

// JWT signing/expiry settings, read from the repo-root .env.
// Used only by the users service (registration, login, session validation).
class AuthConfig 
{
public:
    // Secret key used to sign and verify JWTs (HMAC). Falls back to a
    // non-secret placeholder so the service still boots without a .env -
    // do NOT rely on the default outside local development.
    static std::string JWT_SECRET() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("JWT_SECRET");
        if (!val || std::string(val).empty())
        {
            throw std::runtime_error("JWT_SECRET is not set - refusing to start with a guessable default");
        }
        return std::string(val);
    }

    // JWT signing algorithm name, as passed to the jwt-cpp library.
    static std::string JWT_ALGORITHM() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("JWT_ALGORITHM");
        return val ? std::string(val) : "HS256";
    }

    // How long a token (and its matching user_sessions row) stays valid, in
    // seconds. Default: 86400 = 24 hours. Both the JWT "exp" claim and the
    // session's expires_at column are derived from this single value so
    // they can never disagree.
    static int JWT_EXPIRY_SECS() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("JWT_EXPIRY_SECS");
        return val ? std::stoi(val) : 86400;
    }
};