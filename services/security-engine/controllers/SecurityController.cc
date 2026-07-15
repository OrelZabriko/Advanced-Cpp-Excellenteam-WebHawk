#include "SecurityController.h"
#include "../services/SecurityService.h"

void SecurityController::analyze(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) 
{
    // Parse the JSON body 
    auto json = req->getJsonObject();
    if (!json) 
    {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Invalid JSON body"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    // Validate required fields 
    if (!json->isMember("endpoint") || !json->isMember("method") || !json->isMember("ip")) 
    {
        Json::Value error;
        error["error"] = "Missing required fields: endpoint, method, ip";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    // Pass the full JSON payload to SecurityService for analysis
    SecurityService::analyzeRequest(
        *json,
        [callback](bool allowed, const std::string &attackType, const std::string &reason) {
            Json::Value response;
            response["allowed"] = allowed;
            // Per Contract A (API Contracts doc): always include attack_type
            // and reason, as explicit null on a clean request - not omitted -
            // so the middleware can rely on both fields always being present.
            response["attack_type"] = allowed ? Json::Value::null : Json::Value(attackType);
            response["reason"] = allowed ? Json::Value::null : Json::Value(reason);
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(allowed ? k200OK : k403Forbidden);
            callback(resp);
        },
        [callback](const std::string &error) {
            Json::Value response;
            response["error"] = "Internal server error";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k500InternalServerError);
            callback(resp);
        }
    );
}