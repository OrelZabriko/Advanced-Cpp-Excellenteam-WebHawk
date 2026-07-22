#pragma once

#include <drogon/HttpRequest.h>
#include <json/json.h>

// Converts an incoming client request into the JSON shape Contract A defines
// for POST /analyze (see the API Contracts doc): endpoint, method, ip,
// headers, query_params, path_params, body.
class RequestPayloadBuilder 
{
    public:
        static Json::Value buildAnalyzePayload(const drogon::HttpRequestPtr &req) 
        {
            Json::Value payload;
            payload["endpoint"] = req->path();
            payload["method"] = req->methodString();
            payload["ip"] = req->getPeerAddr().toIp();
        
            Json::Value headers(Json::objectValue);
            for (const auto &header : req->getHeaders()) 
            {
                headers[header.first] = header.second;
            }
            payload["headers"] = headers;
        
            Json::Value queryParams(Json::objectValue);
            for (const auto &param : req->getParameters()) 
            {
                queryParams[param.first] = param.second;
            }
            payload["query_params"] = queryParams;
        
            // This middleware is registered as a single catch-all handler (see
            // main.cc's setDefaultHandler), not a set of routes with named
            // placeholders like "/users/{id}" - so there's no Drogon route
            // pattern to extract named path params from. Always empty here;
            // if named path params are ever needed, security-engine's analyzer
            // doesn't currently use path_params for anything, so this hasn't
            // mattered in practice.
            payload["path_params"] = Json::Value(Json::objectValue);
        
            auto bodyJson = req->getJsonObject();
            if (bodyJson) 
            {
                payload["body"] = *bodyJson;
            } 
            else 
            {
                // Non-JSON or empty body - send an empty object rather than
                // omitting the field, since SecurityService::analyzeRequest
                // always calls requestPayload.get("body", ...) expecting a
                // (possibly empty) JSON value there.
                payload["body"] = Json::Value(Json::objectValue);
            }
        
            return payload;
        }
};