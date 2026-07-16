#include "ProxyService.h"
#include "../clients/ServiceEndpoints.h"
#include "../utils/RequestPayloadBuilder.h"
#include <drogon/HttpClient.h>
#include <json/json.h>

using namespace drogon;

namespace 
{
void sendJsonResponse(const std::function<void(const HttpResponsePtr &)> &callback, const Json::Value &body, HttpStatusCode status) 
{
    auto resp = HttpResponse::newHttpJsonResponse(body);
    resp->setStatusCode(status);
    callback(resp);
}

// Contract C's blocked-response shape - deliberately generic (no `reason`),
// per the API Contracts doc's own note: "Keep the blocked response generic
// enough that it doesn't leak exactly which detection rule fired."
void sendBlockedResponse(const std::function<void(const HttpResponsePtr &)> &callback, const std::string &attackType)
 {
    Json::Value body;
    body["error"] = "Request blocked";
    body["attack_type"] = attackType;
    sendJsonResponse(callback, body, k403Forbidden);
}

void sendInternalError(const std::function<void(const HttpResponsePtr &)> &callback, const std::string &context) 
{
    Json::Value body;
    body["error"] = "Internal server error";
    // Helpful while building/debugging this service; consider removing
    // "context" before a real demo so internal service names aren't exposed.
    body["context"] = context;
    sendJsonResponse(callback, body, k500InternalServerError);
}

// Step 4 (final step on the "allowed" path): forward the request to the
// real backend and pass its response back to the client as-is (Contract C).
void forwardToRealBackend(
    const HttpRequestPtr &req,
    const std::string &targetUrl,
    const std::function<void(const HttpResponsePtr &)> &callback
) 
{
    auto client = HttpClient::newHttpClient(targetUrl);
    auto outboundReq = HttpRequest::newHttpRequest();
    outboundReq->setMethod(req->getMethod());

    std::string path = req->path();
    if (!req->query().empty()) 
    {
        path += "?" + req->query();
    }
    outboundReq->setPath(path);

    // Only a minimal, explicit set of headers is forwarded - blindly copying
    // every incoming header (Host, Content-Length, etc.) is a common source
    // of subtle proxy bugs, so this is a deliberate simplification, not an
    // oversight. Extend this list if the real backend needs to see more of
    // the original request.
    auto authHeader = req->getHeader("Authorization");
    if (!authHeader.empty()) 
    {
        outboundReq->addHeader("Authorization", authHeader);
    }
    auto contentType = req->getHeader("Content-Type");
    if (!contentType.empty()) 
    {
        outboundReq->addHeader("Content-Type", contentType);
    }
    if (!req->body().empty()) 
    {
        outboundReq->setBody(std::string(req->body()));
    }

    client->sendRequest(
        outboundReq,
        [callback](ReqResult result, const HttpResponsePtr &response) {
            if (result != ReqResult::Ok || !response) {
                sendInternalError(callback, "real backend unreachable");
                return;
            }
            // Pass the real backend's response through exactly as-is.
            callback(response);
        }
    );
}

// Step 3: ask security-engine whether this request is safe (Contract A).
void callAnalyze(
    const HttpRequestPtr &req,
    const std::string &targetUrl,
    const std::function<void(const HttpResponsePtr &)> &callback
) 
{
    Json::Value payload = RequestPayloadBuilder::buildAnalyzePayload(req);
    Json::StreamWriterBuilder writer;
    std::string payloadStr = Json::writeString(writer, payload);

    auto client = HttpClient::newHttpClient(ServiceEndpoints::SECURITY_ENGINE);
    auto analyzeReq = HttpRequest::newHttpRequest();
    analyzeReq->setMethod(Post);
    analyzeReq->setPath("/analyze");
    analyzeReq->addHeader("Content-Type", "application/json");
    analyzeReq->setBody(payloadStr);

    client->sendRequest(
        analyzeReq,
        [req, targetUrl, callback](ReqResult result, const HttpResponsePtr &response) {
            if (result != ReqResult::Ok || !response) {
                sendInternalError(callback, "security-engine unreachable");
                return;
            }
            auto json = response->getJsonObject();
            if (!json) {
                sendInternalError(callback, "security-engine returned a non-JSON response");
                return;
            }
            bool allowed = (*json)["allowed"].asBool();
            if (!allowed) {
                std::string attackType = (*json)["attack_type"].isNull() ? "" : (*json)["attack_type"].asString();
                sendBlockedResponse(callback, attackType);
                return;
            }
            forwardToRealBackend(req, targetUrl, callback);
        }
    );
}

// Step 2 (only runs if the caller sent an Authorization header): validate
// the JWT by calling the users service's own /validate endpoint, rather
// than decoding it here. This resolves the open item in the API Contracts
// checklist ("Whether JWTs are validated by the middleware itself or by
// calling into the user service") in favor of the second option - so the
// JWT secret only ever needs to live in one service (users), not two.
void validateJwtIfPresent(
    const HttpRequestPtr &req,
    const std::string &targetUrl,
    const std::function<void(const HttpResponsePtr &)> &callback
) {
    auto authHeader = req->getHeader("Authorization");
    if (authHeader.empty()) 
    {
        // ASSUMPTION: no Authorization header means this particular request
        // doesn't require a logged-in user - not every backend registered
        // with WebHawk necessarily needs authentication on every endpoint.
        // Flag this with the team if every request should instead require
        // a valid JWT unconditionally.
        callAnalyze(req, targetUrl, callback);
        return;
    }

    auto client = HttpClient::newHttpClient(ServiceEndpoints::USERS);
    auto validateReq = HttpRequest::newHttpRequest();
    validateReq->setMethod(Get);
    validateReq->setPath("/validate");
    validateReq->addHeader("Authorization", authHeader);

    client->sendRequest(
        validateReq,
        [req, targetUrl, callback](ReqResult result, const HttpResponsePtr &response) {
            if (result != ReqResult::Ok || !response) {
                sendInternalError(callback, "users service unreachable");
                return;
            }
            auto json = response->getJsonObject();
            bool valid = json && (*json)["valid"].asBool();
            if (!valid) {
                Json::Value body;
                body["error"] = "Invalid or expired token";
                sendJsonResponse(callback, body, k401Unauthorized);
                return;
            }
            callAnalyze(req, targetUrl, callback);
        }
    );
}

} // namespace

void ProxyService::handleRequest(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback
) 
{
    // Step 1: resolve the caller's API key to a registered backend
    // (Contract B). See this file's header comment for the ASSUMPTION
    // about how the key travels on the request (X-API-Key header).
    std::string apiKey = req->getHeader("X-API-Key");
    if (apiKey.empty()) 
    {
        Json::Value body;
        body["error"] = "Missing X-API-Key header";
        sendJsonResponse(callback, body, k401Unauthorized);
        return;
    }

    auto client = HttpClient::newHttpClient(ServiceEndpoints::BACKEND_REGISTRY);
    auto lookupReq = HttpRequest::newHttpRequest();
    lookupReq->setMethod(Get);
    // Built manually (rather than a setParameter-style helper) since apiKey
    // is always plain hex here (see ApiKeyGenerator) - nothing that needs
    // URL-encoding.
    lookupReq->setPath("/backends/lookup?api_key=" + apiKey);

    client->sendRequest(
        lookupReq,
        [req, callback](ReqResult result, const HttpResponsePtr &response) {
            if (result != ReqResult::Ok || !response) {
                sendInternalError(callback, "backend-registry unreachable");
                return;
            }
            auto json = response->getJsonObject();
            if (!json || !(*json)["found"].asBool()) {
                Json::Value body;
                body["error"] = "Unknown API key";
                sendJsonResponse(callback, body, k404NotFound);
                return;
            }
            if (!(*json)["active"].asBool()) {
                Json::Value body;
                body["error"] = "This backend's protection is currently paused";
                sendJsonResponse(callback, body, k403Forbidden);
                return;
            }

            std::string targetUrl = (*json)["target_url"].asString();
            validateJwtIfPresent(req, targetUrl, callback);
        }
    );
}