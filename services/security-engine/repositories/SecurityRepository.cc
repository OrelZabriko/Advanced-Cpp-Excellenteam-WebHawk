#include "SecurityRepository.h"
#include "../../shared/DB_Repository.h"
#include <iostream>

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
    std::string sql =
        "INSERT INTO logs_security (endpoint, method, attack_type, blocked, ip) "
        "VALUES ($1, $2, NULLIF($3, ''), $4, $5);";

    DB_Repository::getInstance().run_update_query_params(
        sql,
        [successCallback](size_t rowsAffected) {
            successCallback();
        },
        errorCallback,
        endpoint, method, attackType, blocked, ip
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
    // Use a prepared statement with $1..$4 to prevent SQL injection.
    // make_interval(secs => $3) safely converts the integer parameter to a
    // PostgreSQL interval, directly in seconds - matching windowSeconds with
    // no unit conversion needed (unlike the old mins => version, this works
    // for any window size, not just whole minutes).
    std::string sql =
        "INSERT INTO limit_rate (endpoint, ip, request_count, window_start, blocked_status) "
        "VALUES ($1, $2, 1, NOW(), FALSE) "
        "ON CONFLICT (ip, endpoint) DO UPDATE SET "
        "request_count = CASE "
            "WHEN NOW() - limit_rate.window_start > make_interval(secs => $3) THEN 1 "
            "ELSE limit_rate.request_count + 1 "
        "END, "
        "window_start = CASE "
            "WHEN NOW() - limit_rate.window_start > make_interval(mins => $3) THEN NOW() "
            "ELSE limit_rate.window_start "
        "END, "
        "blocked_status = CASE "
            "WHEN NOW() - limit_rate.window_start > make_interval(mins => $3) THEN FALSE "
            "WHEN limit_rate.request_count + 1 > $4 THEN TRUE "
            "ELSE limit_rate.blocked_status "
        "END "
        "RETURNING blocked_status;";

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
        endpoint, ip, windowSeconds, maxRequests
    );
}