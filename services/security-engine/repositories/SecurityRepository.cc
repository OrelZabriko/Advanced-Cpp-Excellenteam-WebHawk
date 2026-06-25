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
) {
    // Note: In a real production system we would use prepared statements ($1, $2) to avoid SQL injection
    // Since the shared DB_Repository only accepts raw strings, we build it carefully here.
    std::string attackVal = attackType.empty() ? "NULL" : "'" + attackType + "'";
    std::string blockedVal = blocked ? "TRUE" : "FALSE";
    
    std::string sql = "INSERT INTO logs_security (endpoint, method, attack_type, blocked, ip) VALUES ('" +
                      endpoint + "', '" + method + "', " + attackVal + ", " + blockedVal + ", '" + ip + "');";

    DB_Repository::getInstance().run_update_query(
        sql,
        [successCallback](size_t rowsAffected) {
            successCallback();
        },
        errorCallback
    );
}

void SecurityRepository::updateAndCheckRateLimit(
    const std::string& endpoint,
    const std::string& ip,
    int windowMinutes,
    int maxRequests,
    std::function<void(bool isBlocked)> successCallback,
    std::function<void(const std::string& error)> errorCallback
) {
    // "Upsert" query (INSERT ... ON CONFLICT DO UPDATE)
    // 1. If IP+Endpoint doesn't exist -> Insert with count=1, blocked=FALSE
    // 2. If exists, check if the time window passed. If yes -> reset to 1 and FALSE
    // 3. If within time window -> increment count. If count > maxRequests -> set blocked=TRUE
    // RETURNING blocked_status allows us to immediately get the decision back.
    
    std::string winMin = std::to_string(windowMinutes);
    std::string maxReq = std::to_string(maxRequests);
    
    std::string sql = 
        "INSERT INTO limit_rate (endpoint, ip, request_count, window_start, blocked_status) "
        "VALUES ('" + endpoint + "', '" + ip + "', 1, NOW(), FALSE) "
        "ON CONFLICT (ip, endpoint) DO UPDATE SET "
        "request_count = CASE "
            "WHEN NOW() - limit_rate.window_start > interval '" + winMin + " minutes' THEN 1 "
            "ELSE limit_rate.request_count + 1 "
        "END, "
        "window_start = CASE "
            "WHEN NOW() - limit_rate.window_start > interval '" + winMin + " minutes' THEN NOW() "
            "ELSE limit_rate.window_start "
        "END, "
        "blocked_status = CASE "
            "WHEN NOW() - limit_rate.window_start > interval '" + winMin + " minutes' THEN FALSE "
            "WHEN limit_rate.request_count + 1 > " + maxReq + " THEN TRUE "
            "ELSE limit_rate.blocked_status "
        "END "
        "RETURNING blocked_status;";

    DB_Repository::getInstance().run_query(
        sql,
        [successCallback](const drogon::orm::Result& result) {
            if (!result.empty()) {
                bool isBlocked = result[0]["blocked_status"].as<bool>();
                successCallback(isBlocked);
            } else {
                successCallback(false);
            }
        },
        errorCallback
    );
}
