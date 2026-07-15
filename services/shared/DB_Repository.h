#pragma once

#include <string>
#include <functional>
#include <memory>
#include <drogon/drogon.h>

using DbSelectCallback = std::function<void(const drogon::orm::Result&)>;
using DbUpdateCallback = std::function<void(size_t rowsAffected)>;
using DbErrorCallback  = std::function<void(const std::string& errorMsg)>;

class DB_Repository 
{
private:
    drogon::orm::DbClientPtr dbClient;
    DB_Repository(const std::string& dbClientName = "default");

public:
    DB_Repository(const DB_Repository&) = delete;
    DB_Repository& operator=(const DB_Repository&) = delete;

    static DB_Repository& getInstance();

    // Plain SQL queries (no parameters)
    void run_query(
        const std::string& sqlQuery,
        DbSelectCallback&& successCallback,
        DbErrorCallback&& errorCallback
    );

    void run_update_query(
        const std::string& sqlQuery,
        DbUpdateCallback&& successCallback,
        DbErrorCallback&& errorCallback
    );

    // Parameterized queries (safe from SQL injection)
    template<typename... Args>
    void run_query_params(
        const std::string& sqlQuery,
        DbSelectCallback successCallback,
        DbErrorCallback errorCallback,
        Args&&... args
    ) {
        dbClient->execSqlAsync(
            sqlQuery,
            [successCallback](const drogon::orm::Result& result) {
                successCallback(result);
            },
            [errorCallback](const drogon::orm::DrogonDbException& e) {
                errorCallback(e.base().what());
            },
            std::forward<Args>(args)...
        );
    }

    template<typename... Args>
    void run_update_query_params(
        const std::string& sqlQuery,
        DbUpdateCallback successCallback,
        DbErrorCallback errorCallback,
        Args&&... args
    ) 
    {
        dbClient->execSqlAsync(
            sqlQuery,
            [successCallback](const drogon::orm::Result& result) {
                successCallback(result.affectedRows());
            },
            [errorCallback](const drogon::orm::DrogonDbException& e) {
                errorCallback(e.base().what());
            },
            std::forward<Args>(args)...
        );
    }

    // Auto-build SELECT query
    void runSelectQuery(
        const std::string& sourceTable,
        DbSelectCallback&& successCallback,
        DbErrorCallback&& errorCallback,
        const std::string& selectFields = "*",
        const std::string& condition = ""
    );
};