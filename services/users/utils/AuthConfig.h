#pragma once

#include "../../shared/EnvLoader.h"
#include <cstdlib>
#include <string>
#include <jwt/jwt.hpp>

// JWT signing/expiry settings, read from the repo-root .env.
// Used only by the users service (registration, login, session validation).
class AuthConfig 
{
    public:
        // No hardcoded default on purpose - same principle as DbConfig::PASSWORD().
        // A missing JWT_SECRET means every token this service signs is forgeable
        // by anyone who has read this public repo, so the service must refuse to
        // start rather than silently sign with a known secret.
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
    
        // Raw algorithm name from .env, as-is - no validation, no enum mapping
        // here. Consumed two different ways downstream: passed directly as a
        // string to jwt::decode() (validateToken), or converted to an enum via
        // algorithmEnum() below when signing a new token (loginUser).
        static std::string JWT_ALGORITHM() 
        {
            EnvLoader::ensureLoaded();
            const char* val = std::getenv("JWT_ALGORITHM");
            return val ? std::string(val) : "HS256";
        }
    
        // Maps the string from .env to cpp-jwt's algorithm enum. Only covers
        // the HS-family (HS256/384/512) - cpp-jwt also defines RS256/384/512
        // and ES256/384/512, but those are asymmetric (need a public/private
        // key pair, not the single shared secret() this project uses), so
        // supporting them would need a completely different config shape, not
        // just another enum branch here. HS256 is the only one actually
        // exercised today; HS384/HS512 are included since they're a one-line
        // addition on the same shared-secret model.
        static jwt::algorithm algorithmEnum()
        {
            std::string alg = JWT_ALGORITHM();
            if (alg == "HS256") return jwt::algorithm::HS256;
            if (alg == "HS384") return jwt::algorithm::HS384;
            if (alg == "HS512") return jwt::algorithm::HS512;
            throw std::runtime_error("Unsupported JWT_ALGORITHM: " + alg);
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