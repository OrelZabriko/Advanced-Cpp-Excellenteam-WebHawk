#pragma once

#include <string>
#include <functional>
#include <json/json.h>

// No Drogon include here at all - unlike some other repository headers in
// this project, this one is written so it structurally CANNOT hit the
// "incomplete type" problem: it never names a Drogon DB type (like
// drogon::orm::Result) in its own interface. All of that stays inside
// BackendRepository.cc, which gets the FULL Drogon definitions transitively
// through "../../shared/DB_Repository.h" - so there is only ever one file
// in this class that needs to know Drogon's DB types exist at all.
class BackendRepository 
{
public:
    // Insert a new backend registration. onDuplicate fires if the generated
    // api_key somehow already exists (astronomically unlikely with 128 bits
    // of randomness, but handled the same defensive way UserRepository
    // handles duplicate emails).
    static void insert(
        const std::string& serviceName,
        const std::string& targetUrl,
        const std::string& apiKey,
        std::function<void(int id, const std::string& createdAt)> onSuccess,
        std::function<void()> onDuplicate,
        std::function<void(const std::string& error)> onError
    );

    // Look up a registration by its api_key - this is Contract B's lookup.
    static void findByApiKey(
        const std::string& apiKey,
        std::function<void(int id, const std::string& serviceName, const std::string& targetUrl, bool active)> onFound,
        std::function<void()> onNotFound,
        std::function<void(const std::string& error)> onError
    );

    // Flip a registration's active flag (pause/resume protection without
    // deleting the registration - see the "active" column in the schema doc).
    static void updateActiveStatus(
        int id,
        bool active,
        std::function<void()> onSuccess,
        std::function<void()> onNotFound,
        std::function<void(const std::string& error)> onError
    );

    // List every registered backend - the "management" half of "manage and
    // update registered services". api_key is intentionally NOT included
    // here (see BackendService::listAll for why).
    //
    // Returns already-converted JSON, not a raw drogon::orm::Result - the
    // row-by-row conversion happens inside BackendRepository.cc (which has
    // the full Drogon types available), specifically so this header never
    // has to name a Drogon type to describe what this function returns.
    static void findAll(
        std::function<void(Json::Value backends)> onSuccess,
        std::function<void(const std::string& error)> onError
    );

    // Update a registration's service_name/target_url - the "update" half.
    // Does not touch api_key or active; use updateActiveStatus for active.
    static void update(
        int id,
        const std::string& serviceName,
        const std::string& targetUrl,
        std::function<void()> onSuccess,
        std::function<void()> onNotFound,
        std::function<void(const std::string& error)> onError
    );
};