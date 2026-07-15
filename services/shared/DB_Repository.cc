#include "DB_Repository.h"
#include <stdexcept>

// DB_Repository constructor: Initializes the database client using the provided client name
DB_Repository::DB_Repository(const std::string& dbClientName) {
    dbClient = drogon::app().getDbClient(dbClientName);
    if (!dbClient) {
        throw std::runtime_error("Database Connection Failed: Could not find DB client named '" + dbClientName + "'");
    }
}

// DB_Repository::getInstance: Returns the singleton instance of the repository (Thread-safe)
DB_Repository& DB_Repository::getInstance() {
    static DB_Repository instance; // Created once in the first run.
    return instance;
}

// Run a generic SQL query (SELECT)
void DB_Repository::run_query(
    const std::string& sqlQuery,
    DbSelectCallback&& successCallback,
    DbErrorCallback&& errorCallback
) {
    dbClient->execSqlAsync(
        sqlQuery,
        [successCallback = std::move(successCallback)](const drogon::orm::Result& result) {
            successCallback(result);
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        }
    );
}

// Run an update SQL query (UPDATE/DELETE/INSERT)
void DB_Repository::run_update_query(
    const std::string& sqlQuery,
    DbUpdateCallback&& successCallback,
    DbErrorCallback&& errorCallback
) {
    dbClient->execSqlAsync(
        sqlQuery,
        [successCallback = std::move(successCallback)](const drogon::orm::Result& result) {
            successCallback(result.affectedRows());
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        }
    );
}

// Run a SELECT query with dynamic parameters
void DB_Repository::runSelectQuery(
    const std::string& sourceTable,
    DbSelectCallback&& successCallback,
    DbErrorCallback&& errorCallback,
    const std::string& selectFields,
    const std::string& condition
) 
{
    // Build the SQL query string based on the provided parameters
    std::string sqlQuery = "SELECT " + selectFields + " FROM " + sourceTable;
    
    if (!condition.empty()) 
    {
        sqlQuery += " WHERE " + condition;
    }

    // Call the existing execution function
    run_query(sqlQuery, std::move(successCallback), std::move(errorCallback));
}