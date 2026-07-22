#pragma once

// Global error handling, installed once per service in main.cc before run().
//
// Without these, two request paths escape the per-controller error handling
// that every controller does by hand:
//
//   1. An exception thrown inside a handler that no controller anticipated -
//      most commonly Json::LogicError from asString() on a value that is an
//      object or array rather than a string. Drogon catches these, but its
//      built-in response is HTML, so a client parsing JSON gets a parse error
//      instead of a readable message.
//
//   2. An HTTP-level error Drogon generates on its own, before any handler
//      runs - 404 for an unrouted path, 405 for a wrong method. Same problem:
//      HTML body on an API that is otherwise JSON everywhere.
//
// Both handlers below exist to keep one guarantee: every response this
// service ever produces has a JSON body. Nothing here replaces per-controller
// validation - explicit 400s for missing fields are still the right place to
// catch bad input, because they can say what was wrong. These are the net
// underneath that, not a substitute for it.

#include <drogon/drogon.h>
#include <json/json.h>

namespace ErrorHandlers 
{
    // Maps the status codes Drogon can raise on its own to short client-safe
    // messages. Anything not listed falls back to a generic string, so an
    // unexpected code still yields JSON rather than an empty body.
    inline std::string messageFor(drogon::HttpStatusCode code) 
    {
        switch (code) 
        {
            case drogon::k400BadRequest:          return "Bad request";
            case drogon::k401Unauthorized:        return "Unauthorized";
            case drogon::k403Forbidden:           return "Forbidden";
            case drogon::k404NotFound:            return "Endpoint not found";
            case drogon::k405MethodNotAllowed:    return "Method not allowed";
            case drogon::k413RequestEntityTooLarge: return "Request body too large";
            default:                              return "Request failed";
        }
    }

    // Catches exceptions that escape a request handler.
    //
    // The exception text goes to the log, never to the client. e.what() on a
    // DB or JSON error routinely contains column names, table names, or the
    // raw query - detail that helps you debug and helps an attacker map the
    // system. This mirrors what ProxyService.cc already does when an internal
    // service call fails: log the context, return something generic.
    inline void installExceptionHandler() 
    {
        drogon::app().setExceptionHandler(
            [](const std::exception &e,
               const drogon::HttpRequestPtr &req,
               std::function<void(drogon::HttpResponsePtr &)> &&callback) 
            {
                LOG_ERROR << "unhandled exception on "
                          << req->getMethodString() << " " << req->path()
                          << ": " << e.what();

                Json::Value body;
                body["error"] = "Internal server error";

                auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
                resp->setStatusCode(drogon::k500InternalServerError);
                callback(resp);
            });
    }

    // Replaces Drogon's built-in HTML error pages for status codes it raises
    // itself, before routing reaches any controller.
    inline void installCustomErrorHandler() 
    {
        drogon::app().setCustomErrorHandler(
            [](drogon::HttpStatusCode code) 
            {
                Json::Value body;
                body["error"] = messageFor(code);

                auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
                resp->setStatusCode(code);
                return resp;
            });
    }

    // Convenience: install both. Call this in every service's main.cc.
    inline void installAll() 
    {
        installExceptionHandler();
        installCustomErrorHandler();
    }
}