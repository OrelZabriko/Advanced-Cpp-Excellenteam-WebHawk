#pragma once

#include "../../shared/EnvLoader.h"
#include <cstdlib>
#include <string>

// Rate-limit thresholds, read from the repo-root .env.
// Used only by the security-engine service (SecurityService::analyzeRequest).
class SecurityConfig 
{
public:
    // Max requests allowed per IP+endpoint within RATE_LIMIT_WINDOW_SECS
    // before the request is flagged and blocked.
    static int RATE_LIMIT_MAX_REQUESTS() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("RATE_LIMIT_MAX_REQUESTS");
        return val ? std::stoi(val) : 100;
    }

    // Size of the sliding window, in seconds. Stored in seconds here for
    // consistency with the other *_SECS values in .env, but
    // SecurityRepository::updateAndCheckRateLimit expects whole minutes -
    // see the conversion (and its rounding caveat) in SecurityService.cc.
    static int RATE_LIMIT_WINDOW_SECS() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("RATE_LIMIT_WINDOW_SECS");
        return val ? std::stoi(val) : 60;
    }
};