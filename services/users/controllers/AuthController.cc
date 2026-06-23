#include "AuthController.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>

std::string hashPassword(const std::string &password) {
    CryptoPP::SHA256 hash;
    std::string digest;
    CryptoPP::StringSource s(password, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest)
            )
        )
    );
    return digest;
}

void AuthController::registerUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // 1. Parse the JSON body
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

    // 3. Hash the password
    std::string passwordHash = hashPassword(password);
    if (passwordHash.empty()) {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value("Password hashing failed"));
        resp->setStatusCode(k500InternalServerError);
        callback(resp);
        return;
    }

    // 4. Insert into database
    auto dbClient = drogon::app().getDbClient();
    dbClient->execSqlAsync(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
        [callback](const drogon::orm::Result &result) {
            Json::Value response;
            response["message"] = "User registered successfully";
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k201Created);
            callback(resp);
        },
        [callback](const drogon::orm::DrogonDbException &e) {
            std::string error = e.base().what();
            Json::Value response;
            // Check if it's a duplicate email error
            if (error.find("duplicate key") != std::string::npos) {
                response["error"] = "Email already exists";
                auto resp = HttpResponse::newHttpJsonResponse(response);
                resp->setStatusCode(k409Conflict);
                callback(resp);
            } else {
                response["error"] = "Database error";
                auto resp = HttpResponse::newHttpJsonResponse(response);
                resp->setStatusCode(k500InternalServerError);
                callback(resp);
            }
        },
        email, passwordHash
    );
}

void AuthController::login(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    auto resp = HttpResponse::newHttpJsonResponse(Json::Value("login endpoint - not implemented yet"));
    callback(resp);
}

void AuthController::logout(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    auto resp = HttpResponse::newHttpJsonResponse(Json::Value("logout endpoint - not implemented yet"));
    callback(resp);
}