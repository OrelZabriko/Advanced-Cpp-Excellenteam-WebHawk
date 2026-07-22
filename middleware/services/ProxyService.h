#pragma once

#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <functional>

// The core of WebHawk: this is what runs for every single incoming request
// (see main.cc's setDefaultHandler - there are no other routes in this
// service, this handles literally everything).
//
// Flow (matches the project spec's "Request Flow" section and the API
// Contracts doc):
//   1. Read the caller's API key and resolve it via backend-registry (Contract B).
//   2. Validate the JWT by calling the users service's /validate endpoint -
//      required on every request, no exceptions.
//   3. Send the request to security-engine's /analyze (Contract A).
//   4. If blocked -> return Contract C's blocked response (403) directly,
//      without ever contacting the real backend.
//   5. If allowed -> forward the request to the registered target_url and
//      pass the real backend's response back to the client as-is.
class ProxyService 
{
    public:
        static void handleRequest(
            const drogon::HttpRequestPtr &req,
            std::function<void(const drogon::HttpResponsePtr &)> &&callback
        );
};