#include "AuthController.h"
#include "../services/UserService.h"

void AuthController::registerUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Invalid JSON body"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

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

    UserService::registerUser(
        email, password,
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
    auto json = req->getJsonObject();
    if (!json) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Invalid JSON body"));
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

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

    std::string ip = req->getPeerAddr().toIp();

    UserService::loginUser(
        email, password, ip,
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
    // Extract token from Authorization header
    std::string authHeader = req->getHeader("Authorization");
    if (authHeader.empty() || authHeader.substr(0, 7) != "Bearer ") {
        Json::Value response;
        response["error"] = "Missing or invalid Authorization header";
        auto resp = HttpResponse::newHttpJsonResponse(response);
        resp->setStatusCode(k401Unauthorized);
        callback(resp);
        return;
    }

    std::string token = authHeader.substr(7);

    UserService::logoutUser(
        token,
        [callback]() {
            Json::Value response;
            response["message"] = "Logged out successfully";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k200OK);
            callback(resp);
        },
        [callback]() {
            Json::Value response;
            response["error"] = "Session not found or already revoked";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k404NotFound);
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

void AuthController::validate(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // 1. Extract token from Authorization header
    std::string authHeader = req->getHeader("Authorization");
    if (authHeader.empty() || authHeader.substr(0, 7) != "Bearer ") {
        Json::Value response;
        response["valid"] = false;
        response["reason"] = "Missing or invalid Authorization header";
        auto resp = HttpResponse::newHttpJsonResponse(response);
        resp->setStatusCode(k401Unauthorized);
        callback(resp);
        return;
    }

    std::string token = authHeader.substr(7);

    // 2. Call service
    UserService::validateToken(
        token,
        [callback](int userId) {
            Json::Value response;
            response["valid"] = true;
            response["user_id"] = userId;
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k200OK);
            callback(resp);
        },
        [callback](const std::string &reason) {
            Json::Value response;
            response["valid"] = false;
            response["reason"] = reason;
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k401Unauthorized);
            callback(resp);
        },
        [callback](const std::string &error) {
            Json::Value response;
            response["valid"] = false;
            response["reason"] = "Internal server error";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k500InternalServerError);
            callback(resp);
        }
    );
}