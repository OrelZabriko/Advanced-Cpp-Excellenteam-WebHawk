#include <drogon/drogon.h>
#include "services/ProxyService.h"

int main() 
{
    // No individual routes are registered on purpose - this service is a
    // single "front door" for every request the client sends (see the
    // project spec: "client sends a request to WebHawk instead of the real
    // server"). setDefaultHandler runs for literally every path/method that
    // reaches this service, replacing the default 404 response.
    drogon::app().setDefaultHandler(
        [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback)
        {
            ProxyService::handleRequest(req, std::move(callback));
        }
    );

    // The middleware doesn't talk to Postgres directly (it only calls the
    // other three services over HTTP), so unlike main.cc in the other
    // services, there's no createDbClient() call here.
    drogon::app().loadConfigFile("config.json");
    drogon::app().run();
}