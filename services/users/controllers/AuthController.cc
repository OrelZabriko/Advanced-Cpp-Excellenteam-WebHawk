#include "AuthController.h"
#include "../services/UserService.h"

void AuthController::registerUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // 1. Parse JSON body
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Invalid JSON body"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    // 2. Validate input
    if (!json->isMember("email") || !json->isMember("password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Email and password are required"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    std::string email = (*json)["email"].asString();
    std::string password = (*json)["password"].asString();

    if (email.empty() || password.empty()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Email and password cannot be empty"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    // 3. Call service
    UserService::registerUser(
        email,
        password,
        [callback]() {
            Json::Value response;
            response["message"] = "User registered successfully";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k201Created);
            callback(resp);
        },
        [callback]() {
            Json::Value response;
            response["error"] = "Email already exists";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k409Conflict);
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

void AuthController::login(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // 1. Parse JSON body
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Invalid JSON body"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    // 2. Validate input
    if (!json->isMember("email") || !json->isMember("password")) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Email and password are required"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    std::string email = (*json)["email"].asString();
    std::string password = (*json)["password"].asString();

    if (email.empty() || password.empty()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Email and password cannot be empty"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    // 3. Get client IP
    std::string ip = req->getPeerAddr().toIp();

    // 4. Call service
    UserService::loginUser(
        email,
        password,
        ip,
        [callback](const std::string &token) {
            Json::Value response;
            response["token"] = token;
            response["message"] = "Login successful";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k200OK);
            callback(resp);
        },
        [callback]() {
            Json::Value response;
            response["error"] = "Invalid email or password";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k401Unauthorized);
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

void AuthController::logout(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    auto resp = HttpResponse::newHttpJsonResponse(Json::Value("logout endpoint - not implemented yet"));
    callback(resp);
}