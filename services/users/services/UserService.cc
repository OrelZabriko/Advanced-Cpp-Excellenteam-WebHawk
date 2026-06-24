#include "UserService.h"
#include "../repositories/UserRepository.h"
#include "../utils/HashUtils.h"
#include <jwt/jwt.hpp>
#include <ctime>

void UserService::registerUser(
    const std::string &email,
    const std::string &password,
    std::function<void()> onSuccess,
    std::function<void()> onDuplicate,
    std::function<void(const std::string &error)> onError
) {
    std::string passwordHash = HashUtils::hashPassword(password);

    UserRepository::insert(
        email,
        passwordHash,
        onSuccess,
        onDuplicate,
        onError
    );
}

void UserService::loginUser(
    const std::string &email,
    const std::string &password,
    const std::string &ip,
    std::function<void(const std::string &token)> onSuccess,
    std::function<void()> onInvalidCredentials,
    std::function<void(const std::string &error)> onError
) {
    UserRepository::findByEmail(
        email,
        [password, ip, onSuccess, onInvalidCredentials, onError](int userId, const std::string &storedHash) {
            // Verify password
            if (!HashUtils::verifyPassword(password, storedHash)) {
                onInvalidCredentials();
                return;
            }

            // Generate JWT
            using namespace jwt::params;
            auto token = jwt::jwt_object{
                algorithm("HS256"),
                secret("webhawk_secret_key"),
                payload({
                    {"user_id", std::to_string(userId)},
                    {"exp",     std::to_string(std::time(nullptr) + 86400)}
                })
            };
            std::string tokenStr = token.signature();

            // Insert session
            auto dbClient = drogon::app().getDbClient();
            dbClient->execSqlAsync(
                "INSERT INTO user_sessions (user_id, token_id, ip, expires_at) "
                "VALUES ($1, $2, $3, NOW() + INTERVAL '24 hours')",
                [onSuccess, tokenStr](const drogon::orm::Result &r) {
                    onSuccess(tokenStr);
                },
                [onError](const drogon::orm::DrogonDbException &e) {
                    onError(e.base().what());
                },
                userId, tokenStr, ip
            );
        },
        onInvalidCredentials,
        onError
    );
}