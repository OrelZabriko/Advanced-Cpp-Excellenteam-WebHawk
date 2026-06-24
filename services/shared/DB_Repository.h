#pragma once
#include <string>
#include <functional>
#include <memory>
#include <drogon/drogon.h>

// הגדרות הטיפוסים הכלליות של הפרויקט
using DbSelectCallback = std::function<void(const drogon::orm::Result&)>;
using DbUpdateCallback = std::function<void(size_t rowsAffected)>;
using DbErrorCallback  = std::function<void(const std::string& errorMsg)>;

class DB_Repository {
private:
    drogon::orm::DbClientPtr dbClient;

    DB_Repository(const std::string& dbClientName = "default");

public:
    DB_Repository(const DB_Repository&) = delete;
    DB_Repository& operator=(const DB_Repository&) = delete;

    static DB_Repository& getInstance();

    // callbacks for database operations 
    void run_query(
        const std::string& sqlQuery,
        DbSelectCallback&& successCallback,
        DbErrorCallback&& errorCallback
    );

    // callbacks for database update operations (INSERT, UPDATE, DELETE)
    void run_update_query(
        const std::string& sqlQuery,
        DbUpdateCallback&& successCallback,
        DbErrorCallback&& errorCallback
    );

    // callbacks for database select operations
    void runSelectQuery(
        const std::string& sourceTable,
        DbSelectCallback&& successCallback,
        DbErrorCallback&& errorCallback,
        const std::string& selectFields = "*",
        const std::string& condition = ""
    );
};