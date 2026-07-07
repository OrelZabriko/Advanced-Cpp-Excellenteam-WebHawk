#include "SecurityController.h"
#include "../services/SecurityService.h"

void SecurityController::analyze(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // 1. Parse the JSON body sent by Orel's middleware
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Invalid JSON body"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    // 2. Validate required fields (as defined in the API Contracts doc)
    if (!json->isMember("endpoint") || !json->isMember("method") || !json->isMember("ip")) {
        Json::Value error;
        error["error"] = "Missing required fields: endpoint, method, ip";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    // 3. Pass the full JSON payload to SecurityService for analysis
    SecurityService::analyzeRequest(
        *json,
        [callback](bool allowed, const std::string &attackType, const std::string &reason) {
            Json::Value response;
            response["allowed"] = allowed;
            if (!allowed) {
                response["attack_type"] = attackType;
                response["reason"] = reason;
            }
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
