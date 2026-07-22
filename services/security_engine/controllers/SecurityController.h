#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class SecurityController : public drogon::HttpController<SecurityController> 
{
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(SecurityController::analyze, "/analyze", Post);
    METHOD_LIST_END

    void analyze(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
};