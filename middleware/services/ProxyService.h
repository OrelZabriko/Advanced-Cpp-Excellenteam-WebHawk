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
//   1. Read the caller's API key (see the class-level note on ASSUMPTION
//      below) and resolve it via backend-registry (Contract B).
//   2. (If an Authorization header is present) validate the JWT by calling
//      the users service's /validate endpoint.
//   3. Send the request to security-engine's /analyze (Contract A).
//   4. If blocked -> return Contract C's blocked response (403) directly,
//      without ever contacting the real backend.
//   5. If allowed -> forward the request to the registered target_url and
//      pass the real backend's response back to the client as-is.
//
// ASSUMPTION (flagged, not a locked-in team decision - see the "Decisions
// to lock in together" checklist in the API Contracts doc): the caller
// identifies which registered backend it wants via a dedicated
// "X-API-Key" header. The doc defines the lookup ("given an api_key, find
// the target") but not how that key travels on each request - confirm this
// with Nadav/Benny before treating it as final.
class ProxyService 
{
public:
    static void handleRequest(
        const drogon::HttpRequestPtr &req,
        std::function<void(const drogon::HttpResponsePtr &)> &&callback
    );
};