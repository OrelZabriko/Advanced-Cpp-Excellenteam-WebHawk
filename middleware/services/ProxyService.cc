#include "ProxyService.h"
#include "../clients/ServiceEndpoints.h"
#include "../utils/RequestPayloadBuilder.h"
#include <drogon/HttpClient.h>
#include <drogon/drogon.h>
#include <json/json.h>
#include <algorithm>

using namespace drogon;

namespace 
{
    // Every call this file makes to another internal service uses the same timeout, in seconds. Without it,
    // HttpClient::sendRequest's timeout defaults to 0 ("wait forever") - a single hung service or slow real
    // backend would then tie up the request indefinitely instead of failing fast with a 500.
    constexpr double INTERNAL_CALL_TIMEOUT_SECS = 5.0;

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
        HttpStatusCode status = (attackType == "rate_limit") ? k429TooManyRequests : k403Forbidden;
        sendJsonResponse(callback, body, status);
    }

    // Shared "something went wrong talking to another service" handler - called
    // from all 4 places in this file where the middleware makes an HTTP call to
    // another internal service (backend-registry's lookup, users' /validate,
    // security-engine's /analyze, and the real backend itself) and that call
    // either fails outright (unreachable, timeout) or returns something this
    // code doesn't know how to interpret (e.g. non-JSON where JSON was expected).
    // Always responds with the same generic 500 to the client, regardless of
    // which of the 4 calls actually failed.
    //
    // `context` (e.g. "security-engine unreachable") is logged server-side only,
    // via Drogon's logger - it is NOT sent to the client. An earlier version put
    // it directly in the response body, which meant anyone triggering a 500 saw
    // the internal service names (users/security-engine/backend-registry) that
    // make up this system - useful for attackers mapping the architecture,
    // not something a client ever needs. The client always gets the same
    // generic message regardless of which internal call actually failed.
    void sendInternalError(const std::function<void(const HttpResponsePtr &)> &callback, const std::string &context) 
    {
        LOG_ERROR << "Internal error: " << context;
        Json::Value body;
        body["error"] = "Internal server error";
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
                try 
                {
                    if (result != ReqResult::Ok || !response) 
                    {
                        sendInternalError(callback, "real backend unreachable or timed out");
                        return;
                    }
                    auto newResp = HttpResponse::newHttpResponse();
                    newResp->setStatusCode(response->statusCode());
                    newResp->setBody(std::string(response->body()));
                    for (auto const& [key, value] : response->headers()) 
                    {
                        std::string lowerKey = key;
                        std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
                        if (lowerKey != "content-length" && lowerKey != "transfer-encoding" && lowerKey != "connection") {
                            newResp->addHeader(key, value);
                        }
                    }
                    callback(newResp);
                } 
                catch (const std::exception &e) 
                {
                    sendInternalError(callback, std::string("exception in forwardToRealBackend callback: ") + e.what());
                } 
                catch (...) 
                {
                    sendInternalError(callback, "unknown exception in forwardToRealBackend callback");
                }
            },
            INTERNAL_CALL_TIMEOUT_SECS
        );
    }

    // Step 3: ask security-engine whether this request is safe (Contract A).
    void callAnalyze(
        const HttpRequestPtr &req,
        const std::string &targetUrl,
        const std::function<void(const HttpResponsePtr &)> &callback
    ) 
    {
        Json::Value payload;
        try 
        {
            payload = RequestPayloadBuilder::buildAnalyzePayload(req);
        } 
        catch (const std::exception &e) 
        {
            sendInternalError(callback, std::string("failed to build analyze payload: ") + e.what());
            return;
        } 
        catch (...) 
        {
            sendInternalError(callback, "unknown exception building analyze payload");
            return;
        }

        Json::StreamWriterBuilder writer;
        std::string payloadStr = Json::writeString(writer, payload);

        auto client = HttpClient::newHttpClient(ServiceEndpoints::SECURITY_ENGINE);
        auto analyzeReq = HttpRequest::newHttpJsonRequest(payload);
        analyzeReq->setMethod(Post);
        analyzeReq->setPath("/analyze");

        client->sendRequest(
            analyzeReq,
            [req, targetUrl, callback](ReqResult result, const HttpResponsePtr &response) {
                try 
                {
                    if (result != ReqResult::Ok || !response) 
                    {
                        sendInternalError(callback, "security-engine unreachable or timed out");
                        return;
                    }
                     // Without this check a 5xx from security-engine falls through to the
                    // "allowed" lookup below, where a missing key makes asBool() return
                    // false - so an internal failure would reach the client as a 403
                    // "Request blocked" with an empty attack_type. validateJwt already
                    // guards this way; callAnalyze needs the same.
                    if (response->statusCode() >= k500InternalServerError)
                    {
                        sendInternalError(callback, "security-engine returned an internal error");
                        return;
                    }
                    auto json = response->getJsonObject();
                    if (!json || !json->isObject()) 
                    {
                        sendInternalError(callback, "security-engine returned a non-JSON or non-object response");
                        return;
                    }
                    if (!json->isMember("allowed"))
                    {
                        LOG_ERROR << "security-engine response missing 'allowed'. Raw body: " << response->getBody();
                        sendInternalError(callback, "security-engine returned invalid format");
                        return;
                    }
                    bool allowed = (*json)["allowed"].asBool();
                    if (!allowed) 
                    {
                        std::string attackType = (*json)["attack_type"].isNull() ? "" : (*json)["attack_type"].asString();
                        sendBlockedResponse(callback, attackType);
                        return;
                    }
                    forwardToRealBackend(req, targetUrl, callback);
                } 
                catch (const std::exception &e) 
                {
                    sendInternalError(callback, std::string("exception in callAnalyze callback: ") + e.what());
                } 
                catch (...) 
                {
                    sendInternalError(callback, "unknown exception in callAnalyze callback");
                }
            },
            INTERNAL_CALL_TIMEOUT_SECS
        );
    }

    // Step 2: validate the caller's JWT by calling the users service's own
    // /validate endpoint, rather than decoding it here - so the JWT secret only
    // ever needs to live in one service (users), not two.
    //
    // A valid Authorization header is REQUIRED on every request, with no
    // exceptions: skipping this check when the header is missing would let
    // anyone bypass authentication entirely just by omitting it - the one
    // thing this check exists to prevent. If a registered backend ever needs
    // a genuinely public, no-login endpoint, that requires a deliberate
    // opt-out (e.g. a requires_auth flag on the registration), not an implicit
    // one based on what the caller happened to send.
    void validateJwt(
        const HttpRequestPtr &req,
        const std::string &targetUrl,
        const std::function<void(const HttpResponsePtr &)> &callback
    ) 
    {
        auto authHeader = req->getHeader("Authorization");
        if (authHeader.empty()) 
        {
            Json::Value body;
            body["error"] = "Authorization header required";
            sendJsonResponse(callback, body, k401Unauthorized);
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
                try 
                {
                    if (result != ReqResult::Ok || !response) 
                    {
                        sendInternalError(callback, "users service unreachable or timed out");
                        return;
                    }
                    if (response->statusCode() >= k500InternalServerError)
                    {
                        sendInternalError(callback, "users service returned an internal error");
                        return;
                    }
                    auto json = response->getJsonObject();
                    bool valid = json && json->isObject() && (*json)["valid"].asBool();
                    if (!valid) 
                    {
                        Json::Value body;
                        body["error"] = "Invalid or expired token";
                        sendJsonResponse(callback, body, k401Unauthorized);
                        return;
                    }
                    callAnalyze(req, targetUrl, callback);
                } 
                catch (const std::exception &e) 
                {
                    sendInternalError(callback, std::string("exception in validateJwt callback: ") + e.what());
                } 
                catch (...) 
                {
                    sendInternalError(callback, "unknown exception in validateJwt callback");
                }
            },
            INTERNAL_CALL_TIMEOUT_SECS
        );
    }
} // end of setting namespace

void ProxyService::handleRequest(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback
) 
{
    // Step 1: resolve the caller's API key to a registered backend (Contract B). See this file's
    // header comment for how the key is expected to travel on the request (X-API-Key header).
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
    // setParameter rather than embedding the query in setPath: Drogon
    // URL-encodes the path before sending, which would turn '?' and '='
    // into %3F/%3D and break the lookup.
    lookupReq->setPath("/backends/lookup");
    lookupReq->setParameter("api_key", apiKey);

    client->sendRequest(
        lookupReq,
        [req, callback](ReqResult result, const HttpResponsePtr &response) {
            try {
                if (result != ReqResult::Ok || !response) 
                {
                    sendInternalError(callback, "backend-registry unreachable or timed out");
                    return;
                }

                auto json = response->getJsonObject();
                if (!json || !json->isObject() || !(*json)["found"].asBool()) 
                {
                    Json::Value body;
                    body["error"] = "Unknown API key";
                    sendJsonResponse(callback, body, k404NotFound);
                    return;
                }

                if (!(*json)["active"].asBool()) 
                {
                    Json::Value body;
                    body["error"] = "This backend's protection is currently paused";
                    sendJsonResponse(callback, body, k403Forbidden);
                    return;
                }

                std::string targetUrl = (*json)["target_url"].asString();
                validateJwt(req, targetUrl, callback);
            } 
            catch (const std::exception &e) 
            {
                sendInternalError(callback, std::string("exception in lookup callback: ") + e.what());
            } 
            catch (...) 
            {
                sendInternalError(callback, "unknown exception in lookup callback");
            }
        },
        INTERNAL_CALL_TIMEOUT_SECS
    );
}