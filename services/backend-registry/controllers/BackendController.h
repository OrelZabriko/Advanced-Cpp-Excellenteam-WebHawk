#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class BackendController : public drogon::HttpController<BackendController> 
{
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(BackendController::registerBackend, "/backends", Post);
    ADD_METHOD_TO(BackendController::lookup, "/backends/lookup", Get);
    ADD_METHOD_TO(BackendController::listAll, "/backends", Get);
    ADD_METHOD_TO(BackendController::updateBackend, "/backends/{1}", Put);
    ADD_METHOD_TO(BackendController::setStatus, "/backends/{1}/status", Patch);
    METHOD_LIST_END

    // Register a new backend to protect. Body: { service_name, target_url }.
    // Returns the generated api_key - this is the ONLY time the raw key is
    // ever returned, so the caller must store it (matches how a real API
    // key / secret is typically issued: shown once at creation time).
    void registerBackend(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);

    // Contract B: GET /backends/lookup?api_key=... - resolves an API key to
    // a target backend. Called by the middleware on every proxied request.
    void lookup(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);

    // GET /backends - lists every registered backend (never includes
    // api_key - see BackendService::listAll). The "management" half of
    // "manage and update registered services".
    void listAll(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);

    // PUT /backends/{id} - Body: { service_name, target_url }. The "update"
    // half - changes what a registration points at, not its key or status.
    void updateBackend(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int id);

    // PATCH /backends/{id}/status - Body: { "active": true|false }.
    // Lets a developer pause/resume protection without deleting the
    // registration (see the "active" column's purpose in the schema doc).
    void setStatus(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int id);
};