#include "BackendService.h"
#include "../repositories/BackendRepository.h"
#include "../utils/ApiKeyGenerator.h"

void BackendService::registerBackend(
    const std::string& serviceName,
    const std::string& targetUrl,
    std::function<void(int id, const std::string& apiKey, const std::string& createdAt)> onSuccess,
    std::function<void(const std::string& error)> onError
) 
{
    std::string apiKey = ApiKeyGenerator::generate();

    BackendRepository::insert(
        serviceName, targetUrl, apiKey,
        [onSuccess, apiKey](int id, const std::string& createdAt) {
            onSuccess(id, apiKey, createdAt);
        },
        // A duplicate api_key is vanishingly unlikely (128 bits of
        // randomness), but if it ever happens the honest answer is
        // "something is wrong with key generation", not a normal API
        // error - so this surfaces as an error rather than a silent retry.
        [onError]() {
            onError("Generated API key collided with an existing one - this should not happen; please retry");
        },
        onError
    );
}

void BackendService::lookupByApiKey(
    const std::string& apiKey,
    std::function<void(bool found, const std::string& serviceName, const std::string& targetUrl, bool active)> onResult,
    std::function<void(const std::string& error)> onError
) 
{
    BackendRepository::findByApiKey(
        apiKey,
        [onResult](int id, const std::string& serviceName, const std::string& targetUrl, bool active) {
            (void)id; // not part of Contract B's response shape
            onResult(true, serviceName, targetUrl, active);
        },
        [onResult]() {
            onResult(false, "", "", false);
        },
        onError
    );
}

void BackendService::setActiveStatus(
    int id,
    bool active,
    std::function<void()> onSuccess,
    std::function<void()> onNotFound,
    std::function<void(const std::string& error)> onError
) 
{
    BackendRepository::updateActiveStatus(id, active, onSuccess, onNotFound, onError);
}

void BackendService::listAll(
    std::function<void(Json::Value backends)> onSuccess,
    std::function<void(const std::string& error)> onError
) 
{
    // BackendRepository::findAll already returns ready-to-use JSON (with
    // api_key omitted) - nothing left for this layer to transform, so this
    // is a direct pass-through.
    BackendRepository::findAll(onSuccess, onError);
}

void BackendService::updateBackend(
    int id,
    const std::string& serviceName,
    const std::string& targetUrl,
    std::function<void()> onSuccess,
    std::function<void()> onNotFound,
    std::function<void(const std::string& error)> onError
) 
{
    BackendRepository::update(id, serviceName, targetUrl, onSuccess, onNotFound, onError);
}