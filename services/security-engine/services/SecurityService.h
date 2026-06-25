#pragma once

#include <string>
#include <functional>
#include <json/json.h>

class SecurityService {
public:
    // Basic Difficulty: SQL Injection detector
    static bool detectSQLi(const std::string& input);
    
    // Basic Difficulty: Cross-Site Scripting (XSS) detector
    static bool detectXSS(const std::string& input);

    // The single entry point that Orel's Middleware will call.
    // It takes the full JSON payload from the middleware, runs all checks,
    // records the outcome to the DB, and returns the verdict via callback.
    static void analyzeRequest(
        const Json::Value& requestPayload, 
        std::function<void(bool allowed, const std::string& attackType, const std::string& reason)> successCallback,
        std::function<void(const std::string& error)> errorCallback
    );
};
