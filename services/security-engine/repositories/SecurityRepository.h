#pragma once

#include <string>
#include <functional>

class SecurityRepository 
{
public:
    // Log the outcome of a request analysis into the logs_security table
    static void logRequest(
        const std::string& endpoint,
        const std::string& method,
        const std::string& attackType,
        bool blocked,
        const std::string& ip,
        std::function<void()> successCallback,
        std::function<void(const std::string& error)> errorCallback
    );

    // Increment request count for the IP+endpoint and determine if rate limit is exceeded
    static void updateAndCheckRateLimit(
        const std::string& endpoint,
        const std::string& ip,
        int windowMinutes,
        int maxRequests,
        std::function<void(bool isBlocked)> successCallback,
        std::function<void(const std::string& error)> errorCallback
    );
};