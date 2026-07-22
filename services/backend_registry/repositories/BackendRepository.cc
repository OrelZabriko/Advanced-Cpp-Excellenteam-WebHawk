#include "BackendRepository.h"
#include "../../shared/DB_Repository.h"

void BackendRepository::insert(
    const std::string& serviceName,
    const std::string& targetUrl,
    const std::string& apiKey,
    std::function<void(int id, const std::string& createdAt)> onSuccess,
    std::function<void()> onDuplicate,
    std::function<void(const std::string& error)> onError
) 
{
    // RETURNING id, created_at so the caller can build the full registration
    // response without a second round-trip to the DB.
    DB_Repository::getInstance().run_query_params(
        "INSERT INTO backend_registration (service_name, target_url, api_key) "
        "VALUES ($1, $2, $3) RETURNING id, created_at;",
        [onSuccess](const drogon::orm::Result& result) {
            int id = result[0]["id"].as<int>();
            std::string createdAt = result[0]["created_at"].as<std::string>();
            onSuccess(id, createdAt);
        },
        [onDuplicate, onError](const std::string& error) {
            // Same duplicate-detection pattern as UserRepository::insert -
            // relies on the api_key UNIQUE constraint in backend_registry.sql.
            if (error.find("duplicate key") != std::string::npos) onDuplicate();
            else onError(error);
        },
        serviceName, targetUrl, apiKey
    );
}

void BackendRepository::findByApiKey(
    const std::string& apiKey,
    std::function<void(int id, const std::string& serviceName, const std::string& targetUrl, bool active)> onFound,
    std::function<void()> onNotFound,
    std::function<void(const std::string& error)> onError
) 
{
    DB_Repository::getInstance().run_query_params(
        "SELECT id, service_name, target_url, active FROM backend_registration WHERE api_key = $1",
        [onFound, onNotFound](const drogon::orm::Result& result) {
            if (result.empty()) 
            {
                onNotFound();
            } 
            else 
            {
                int id = result[0]["id"].as<int>();
                std::string serviceName = result[0]["service_name"].as<std::string>();
                std::string targetUrl = result[0]["target_url"].as<std::string>();
                bool active = result[0]["active"].as<bool>();
                onFound(id, serviceName, targetUrl, active);
            }
        },
        [onError](const std::string& error) {
            onError(error);
        },
        apiKey
    );
}

void BackendRepository::updateActiveStatus(
    int id,
    bool active,
    std::function<void()> onSuccess,
    std::function<void()> onNotFound,
    std::function<void(const std::string& error)> onError
) 
{
    DB_Repository::getInstance().run_update_query_params(
        "UPDATE backend_registration SET active = $1::boolean WHERE id = $2::integer",
        [onSuccess, onNotFound](size_t rowsAffected) {
            if (rowsAffected == 0) onNotFound();
            else onSuccess();
        },
        [onError](const std::string& error) {
            onError(error);
        },
        std::string(active ? "true" : "false"), std::to_string(id)
    );
}

void BackendRepository::findAll(
    std::function<void(Json::Value backends)> onSuccess,
    std::function<void(const std::string& error)> onError
) 
{
    // api_key deliberately excluded from this query - see
    // BackendService::listAll for why a list view never returns raw keys.
    DB_Repository::getInstance().run_query(
        "SELECT id, service_name, target_url, active, created_at FROM backend_registration ORDER BY id",
        [onSuccess](const drogon::orm::Result& result) {
            // The row-by-row conversion happens HERE, inside this .cc file. drogon::orm::Result also appears above in insert() and
            // findByApiKey() (any query that reads rows back needs it) - but it never crosses into BackendRepository.h or into
            // BackendService.cc/.h, which is the property that actually matters: no other file in backend-registry needs to know
            // this type exists, so the "incomplete type" problem we hit before can't recur outside this one file.
            Json::Value list(Json::arrayValue);
            for (const auto &row : result) 
            {
                Json::Value item;
                item["id"] = row["id"].as<int>();
                item["service_name"] = row["service_name"].as<std::string>();
                item["target_url"] = row["target_url"].as<std::string>();
                item["active"] = row["active"].as<bool>();
                item["created_at"] = row["created_at"].as<std::string>();
                list.append(item);
            }
            onSuccess(list);
        },
        [onError](const std::string& error) {
            onError(error);
        }
    );
}

void BackendRepository::update(
    int id,
    const std::string& serviceName,
    const std::string& targetUrl,
    std::function<void()> onSuccess,
    std::function<void()> onNotFound,
    std::function<void(const std::string& error)> onError
) 
{
    DB_Repository::getInstance().run_update_query_params(
        "UPDATE backend_registration SET service_name = $1, target_url = $2 WHERE id = $3::integer",
        [onSuccess, onNotFound](size_t rowsAffected) {
            if (rowsAffected == 0) onNotFound();
            else onSuccess();
        },
        [onError](const std::string& error) {
            onError(error);
        },
        serviceName, targetUrl, std::to_string(id)
    );
}