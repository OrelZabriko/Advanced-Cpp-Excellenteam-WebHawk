#include "SecurityService.h"
#include "../repositories/SecurityRepository.h"
#include "../utils/SecurityConfig.h"
#include <algorithm>
#include <regex>
#include <iostream>

// ============================================================
// SQL Injection Detector:
// Scans input for known SQLi patterns and returns true if a SQLi pattern is detected.
// ============================================================
bool SecurityService::detectSQLi(const std::string& input) 
{
    // Convert input to lowercase for case insensitive matching
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Known SQL injection patterns from the project spec
    std::vector<std::regex> patterns = {
        std::regex("('\\s*(or|and)\\s+.*=.*--)"),          // ' OR 1=1 --
        std::regex("(union\\s+(all\\s+)?select)"),          // UNION SELECT / UNION ALL SELECT
        std::regex("(drop\\s+table)"),                      // DROP TABLE
        std::regex("(;\\s*(delete|drop|insert|update)\\s)"),// ; DELETE FROM / ; DROP ...
        std::regex("('\\s*;\\s*--)"),                       // '; --
        std::regex("(\\b(select|insert|update|delete)\\b.*[';]|--).*\\b(from|into|set)\\b", std::regex::icase),
        std::regex("(1\\s*=\\s*1)"),                        // 1=1
        std::regex("('\\s*or\\s+'.*'\\s*=\\s*')"),          // ' or 'a'='a'
    };

    for (const auto& pattern : patterns) 
    {
        if (std::regex_search(lower, pattern)) return true;
    }
    return false;
}

// ============================================================
// Cross-Site Scripting (XSS) Detector:
// Scans input for script tags and dangerous event handlers and
// returns true if an XSS pattern is detected.
// ============================================================
bool SecurityService::detectXSS(const std::string& input) 
{
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    std::vector<std::regex> patterns = {
        std::regex("(<\\s*script.*?>)"),                                // <script> tags
        std::regex("(javascript\\s*:)"),                                // javascript: URI
        std::regex("(on(load|error|click|mouseover|focus|blur)\\s*=)"), // Inline event handlers
        std::regex("(<\\s*iframe.*?>)"),                                // <iframe> tags
        std::regex("(<\\s*object.*?>)"),                                // <object> tags
    };

    for (const auto& pattern : patterns) 
    {
        if (std::regex_search(lower, pattern)) return true;
    }
    return false;
}

// ============================================================
// extract all string values from a JSON object
// so we can scan every text field the client sent us.
// For example, from: { "body": { "comment": "hello" }, "query_params": { "q": "test" } }
// it will return: ["hello", "test"]
// ============================================================
static void collectAllStrings(const Json::Value& node, std::vector<std::string>& out) 
{
    if (node.isString()) 
    {
        out.push_back(node.asString());
    } 
    else if (node.isObject()) 
    {
        for (const auto& key : node.getMemberNames()) 
        {
            collectAllStrings(node[key], out);
        }
    } 
    else if (node.isArray()) 
    {
        for (const auto& item : node) 
        {
            collectAllStrings(item, out);
        }
    }
}

// ============================================================
// Part 1: analyzeRequest (SQLi + XSS only)
// Receives the full JSON payload from the middleware,
// extracts all text fields, and runs SQLi + XSS detection.
// ============================================================
void SecurityService::analyzeRequest(
    const Json::Value& requestPayload,
    std::function<void(bool allowed, const std::string& attackType, const std::string& reason)> successCallback,
    std::function<void(const std::string& error)> errorCallback
) 
{
    // Extract request metadata from the JSON (as defined in API Contracts doc)
    std::string endpoint = requestPayload.get("endpoint", "").asString();
    std::string method   = requestPayload.get("method", "").asString();
    std::string ip       = requestPayload.get("ip", "").asString();

    // Collect all string values from body, query_params, path_params
    std::vector<std::string> allTexts;
    collectAllStrings(requestPayload.get("query_params", Json::nullValue), allTexts);
    collectAllStrings(requestPayload.get("path_params", Json::nullValue), allTexts);
    collectAllStrings(requestPayload.get("body", Json::nullValue), allTexts);
    collectAllStrings(requestPayload.get("headers", Json::nullValue), allTexts);

    // --- Check 1: SQL Injection ---
    for (const auto& text : allTexts) 
    {
        if (detectSQLi(text)) 
        {
            // Log to DB and return blocked verdict
            SecurityRepository::logRequest(endpoint, method, "sqli", true, ip,
                [successCallback]() 
                {
                    successCallback(false, "sqli", "SQL injection pattern detected");
                },
                errorCallback
            );
            return;
        }
    }

    // --- Check 2: XSS ---
    for (const auto& text : allTexts) 
    {
        if (detectXSS(text)) 
        {
            SecurityRepository::logRequest(endpoint, method, "xss", true, ip,
                [successCallback]() 
                {
                    successCallback(false, "xss", "XSS pattern detected");
                },
                errorCallback
            );
            return;
        }
    }

    // --- Check 3: Rate Limiting 
    // Track requests per IP per endpoint in a sliding window, sized directly
    // in seconds from .env (see SecurityConfig.h) - no unit conversion, so
    // no precision loss for windows that aren't a whole number of minutes.
    SecurityRepository::updateAndCheckRateLimit(
        endpoint, ip,
        SecurityConfig::RATE_LIMIT_WINDOW_SECS(),
        SecurityConfig::RATE_LIMIT_MAX_REQUESTS(),
        [endpoint, method, ip, successCallback, errorCallback](bool isBlocked) {
            if (isBlocked) 
            {
                // Rate limit exceeded - log and block
                SecurityRepository::logRequest(endpoint, method, "rate_limit", true, ip,
                    [successCallback]() {
                        successCallback(false, "rate_limit", "Rate limit exceeded for this IP");
                    },
                    errorCallback
                );
            } 
            else 
            {
                // All checks passed - log as clean and allow
                SecurityRepository::logRequest(endpoint, method, "", false, ip,
                    [successCallback]() {
                        successCallback(true, "", "");
                    },
                    errorCallback
                );
            }
        },
        errorCallback
    );
}