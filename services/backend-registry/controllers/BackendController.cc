#include "BackendController.h"
#include "../services/BackendService.h"
#include <vector>

void BackendController::registerBackend(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) 
{
    auto json = req->getJsonObject();
    if (!json) 
    {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Invalid JSON body"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    if (!json->isMember("service_name") || !json->isMember("target_url")) 
    {
        Json::Value error;
        std::vector<std::string> missing;
        if (!json->isMember("service_name")) missing.push_back("service_name");
        if (!json->isMember("target_url")) missing.push_back("target_url");

        std::string missingStr;
        for (size_t i = 0; i < missing.size(); ++i) 
        {
            missingStr += missing[i];
            if (i + 1 < missing.size()) missingStr += ", ";
        }
        
        error["error"] = "Missing required field(s): " + missingStr;
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    std::string serviceName = (*json)["service_name"].asString();
    std::string targetUrl = (*json)["target_url"].asString();

    if (serviceName.empty() || targetUrl.empty()) 
    {
        Json::Value error;
        error["error"] = "service_name and target_url cannot be empty";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    if (targetUrl.rfind("http://", 0) != 0 && targetUrl.rfind("https://", 0) != 0)
    {
        Json::Value error;
        error["error"] = "target_url must start with http:// or https://";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    BackendService::registerBackend(
        serviceName, targetUrl,
        [callback, serviceName, targetUrl](int id, const std::string &apiKey, const std::string &createdAt) {
            Json::Value response;
            response["id"] = id;
            response["service_name"] = serviceName;
            response["target_url"] = targetUrl;
            // Shown here once, at creation time, exactly like a real secret/API
            // key issuance flow - the caller must save this now.
            response["api_key"] = apiKey;
            response["active"] = true;
            response["created_at"] = createdAt;
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k201Created);
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

void BackendController::lookup(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) 
{
    std::string apiKey = req->getParameter("api_key");

    if (apiKey.empty()) 
    {
        Json::Value error;
        error["error"] = "Missing required query parameter: api_key";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    BackendService::lookupByApiKey(
        apiKey,
        [callback](bool found, const std::string &serviceName, const std::string &targetUrl, bool active) {
            Json::Value response;
            response["found"] = found;
            if (found) {
                response["service_name"] = serviceName;
                response["target_url"] = targetUrl;
                response["active"] = active;
            }
            // 200 either way - per Contract B, "not found" is a normal,
            // expected business outcome for this endpoint, not an HTTP error.
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k200OK);
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

void BackendController::listAll(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) 
{
    BackendService::listAll(
        [callback](Json::Value backends) {
            Json::Value response;
            response["backends"] = backends;
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k200OK);
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

void BackendController::updateBackend(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int id) 
{
    auto json = req->getJsonObject();
    if (!json || !json->isMember("service_name") || !json->isMember("target_url")) 
    {
        Json::Value error;
        error["error"] = "Missing required fields: service_name, target_url";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    std::string serviceName = (*json)["service_name"].asString();
    std::string targetUrl = (*json)["target_url"].asString();

    if (serviceName.empty() || targetUrl.empty()) 
    {
        Json::Value error;
        error["error"] = "service_name and target_url cannot be empty";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    if (targetUrl.rfind("http://", 0) != 0 && targetUrl.rfind("https://", 0) != 0)
    {
        Json::Value error;
        error["error"] = "target_url must start with http:// or https://";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    BackendService::updateBackend(
        id, serviceName, targetUrl,
        [callback, id, serviceName, targetUrl]() 
        {
            Json::Value response;
            response["id"] = id;
            response["service_name"] = serviceName;
            response["target_url"] = targetUrl;
            response["message"] = "Backend updated successfully";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k200OK);
            callback(resp);
        },
        [callback]() {
            Json::Value response;
            response["error"] = "Backend registration not found";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k404NotFound);
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

void BackendController::setStatus(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int id) 
{
    auto json = req->getJsonObject();
    if (!json || !json->isMember("active")) 
    {
        Json::Value error;
        error["error"] = "Missing required field: active (boolean)";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    bool active = (*json)["active"].asBool();

    BackendService::setActiveStatus(
        id, active,
        [callback, id, active]() {
            Json::Value response;
            response["id"] = id;
            response["active"] = active;
            response["message"] = "Status updated successfully";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k200OK);
            callback(resp);
        },
        [callback]() {
            Json::Value response;
            response["error"] = "Backend registration not found";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k404NotFound);
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