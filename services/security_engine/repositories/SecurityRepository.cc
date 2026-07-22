#include "SecurityRepository.h"
#include "../../shared/DB_Repository.h"
#include <iostream>
#include <string>

void SecurityRepository::logRequest(
    const std::string& endpoint,
    const std::string& method,
    const std::string& attackType,
    bool blocked,
    const std::string& ip,
    std::function<void()> successCallback,
    std::function<void(const std::string& error)> errorCallback
) 
{
    // Use a prepared statement with $1..$5 to prevent SQL injection.
    // NULLIF($3, '') stores NULL in attack_type when the request is clean (empty string).
    // All parameters are passed as strings 
    std::string sql =
        "INSERT INTO security_logs (endpoint, method, attack_type, blocked, ip) "
        "VALUES ($1, $2, NULLIF($3, ''), $4::boolean, $5);";

    // Convert bool to string "true"/"false" so libpq receives it as text, not binary.
    std::string blockedStr = blocked ? "true" : "false";

    DB_Repository::getInstance().run_update_query_params(
        sql,
        [successCallback](size_t rowsAffected) {
            successCallback();
        },
        errorCallback,
        endpoint, method, attackType, blockedStr, ip
    );
}

void SecurityRepository::updateAndCheckRateLimit(
    const std::string& endpoint,
    const std::string& ip,
    int windowSeconds,
    int maxRequests,
    std::function<void(bool isBlocked)> successCallback,
    std::function<void(const std::string& error)> errorCallback
) 
{
    // All numeric parameters are passed as strings to avoid libpq binary format issues.
    // make_interval(secs => $3::integer) converts the text back to a number server side.
    std::string sql =
        "INSERT INTO rate_limit (endpoint, ip, request_count, window_start, blocked_status) "
        "VALUES ($1, $2, 1, NOW(), FALSE) "
        "ON CONFLICT (ip, endpoint) DO UPDATE SET "
        "request_count = CASE "
            "WHEN NOW() - rate_limit.window_start > make_interval(secs => $3::integer) THEN 1 "
            "ELSE rate_limit.request_count + 1 "
        "END, "
        "window_start = CASE "
            "WHEN NOW() - rate_limit.window_start > make_interval(secs => $3::integer) THEN NOW() "
            "ELSE rate_limit.window_start "
        "END, "
        "blocked_status = CASE "
            "WHEN NOW() - rate_limit.window_start > make_interval(secs => $3::integer) THEN FALSE "
            "WHEN rate_limit.request_count + 1 > $4::integer THEN TRUE "
            "ELSE rate_limit.blocked_status "
        "END "
        "RETURNING blocked_status;";

    // Convert ints to strings so libpq receives them as text parameters.
    std::string windowStr = std::to_string(windowSeconds);
    std::string maxReqStr = std::to_string(maxRequests);

    DB_Repository::getInstance().run_query_params(
        sql,
        [successCallback](const drogon::orm::Result& result) {
            if (!result.empty()) {
                bool isBlocked = result[0]["blocked_status"].as<bool>();
                successCallback(isBlocked);
            } else {
                successCallback(false);
            }
        },
        errorCallback,
        endpoint, ip, windowStr, maxReqStr
    );
}