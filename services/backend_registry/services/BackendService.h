#pragma once

#include <string>
#include <functional>
#include <json/json.h>

class BackendService 
{
    public:
        // Registers a new backend and issues it a fresh API key. onSuccess gives
        // back everything a caller needs to display/store: the generated id,
        // api_key, and created_at (service_name/target_url are already known to
        // the caller since it just sent them).
        static void registerBackend(
            const std::string& serviceName,
            const std::string& targetUrl,
            std::function<void(int id, const std::string& apiKey, const std::string& createdAt)> onSuccess,
            std::function<void(const std::string& error)> onError
        );
    
        // Contract B: resolves an API key to where a request should be forwarded.
        // onResult always fires (never onError for "not found" - that's a valid,
        // expected outcome per Contract B's { "found": false } response, not a
        // failure) - onError is reserved for genuine DB/infra problems.
        static void lookupByApiKey(
            const std::string& apiKey,
            std::function<void(bool found, const std::string& serviceName, const std::string& targetUrl, bool active)> onResult,
            std::function<void(const std::string& error)> onError
        );
    
        // Pause or resume protection for a registration without deleting it.
        static void setActiveStatus(
            int id,
            bool active,
            std::function<void()> onSuccess,
            std::function<void()> onNotFound,
            std::function<void(const std::string& error)> onError
        );
    
        // Lists every registered backend, for the "management" part of the
        // spec ("registration + issuing keys + managing/updating registered
        // services"). Deliberately does NOT include api_key in the listing -
        // the key is shown once at creation (see registerBackend) and never
        // again, the same way a real secret/API key is normally handled;
        // returning it again here would mean anyone with list access could
        // read out every backend's live credential.
        static void listAll(
            std::function<void(Json::Value backends)> onSuccess,
            std::function<void(const std::string& error)> onError
        );
    
        // Updates a registration's service_name/target_url (not its api_key or
        // active flag - see setActiveStatus for pausing/resuming).
        static void updateBackend(
            int id,
            const std::string& serviceName,
            const std::string& targetUrl,
            std::function<void()> onSuccess,
            std::function<void()> onNotFound,
            std::function<void(const std::string& error)> onError
        );
};