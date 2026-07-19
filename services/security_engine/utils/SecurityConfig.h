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

    // Size of the sliding window, in seconds. Kept in seconds end-to-end -
    // SecurityConfig -> SecurityService -> SecurityRepository -> SQL's
    // make_interval(secs => ...) - with no unit conversion anywhere in that
    // chain. Don't convert this to minutes: an earlier version did, and the
    // rounding silently changed the real rate-limit window (see README.md).
    static int RATE_LIMIT_WINDOW_SECS() 
    {
        EnvLoader::ensureLoaded();
        const char* val = std::getenv("RATE_LIMIT_WINDOW_SECS");
        return val ? std::stoi(val) : 60;
    }
};