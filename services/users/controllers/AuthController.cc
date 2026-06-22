#include "AuthController.h"

void AuthController::registerUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    auto resp = HttpResponse::newHttpJsonResponse(Json::Value("register endpoint - not implemented yet"));
    callback(resp);
}

void AuthController::login(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    auto resp = HttpResponse::newHttpJsonResponse(Json::Value("login endpoint - not implemented yet"));
    callback(resp);
}

void AuthController::logout(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    auto resp = HttpResponse::newHttpJsonResponse(Json::Value("logout endpoint - not implemented yet"));
    callback(resp);
}