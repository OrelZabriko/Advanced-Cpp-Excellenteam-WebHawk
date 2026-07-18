#include "UserService.h"
#include "../utils/AuthConfig.h"
#include "../repositories/UserRepository.h"
#include "../repositories/SessionRepository.h"
#include "../utils/HashUtils.h"
#include <jwt/jwt.hpp>
#include <ctime>

void UserService::registerUser(
    const std::string &email,
    const std::string &password,
    std::function<void()> onSuccess,
    std::function<void()> onDuplicate,
    std::function<void(const std::string &error)> onError
) 
{
    std::string passwordHash = HashUtils::hashPassword(password);
    UserRepository::insert(email, passwordHash, onSuccess, onDuplicate, onError);
}

void UserService::loginUser(
    const std::string &email,
    const std::string &password,
    const std::string &ip,
    std::function<void(const std::string &token)> onSuccess,
    std::function<void()> onInvalidCredentials,
    std::function<void(const std::string &error)> onError
) 
{
    UserRepository::findByEmail(
        email,
        [password, ip, onSuccess, onInvalidCredentials, onError](int userId, const std::string &storedHash) {
            if (!HashUtils::verifyPassword(password, storedHash)) 
            {
                onInvalidCredentials();
                return;
            }

            using namespace jwt::params;
            auto token = jwt::jwt_object{
                algorithm(AuthConfig::algorithmEnum()),
                secret(AuthConfig::JWT_SECRET()),
                payload({
                    {"user_id", std::to_string(userId)},
                })
            };
            token.add_claim("exp", std::time(nullptr) + AuthConfig::JWT_EXPIRY_SECS());

            std::string tokenStr = token.signature();

            SessionRepository::insert(
                userId, tokenStr, ip,
                [onSuccess, tokenStr]() {
                    onSuccess(tokenStr);
                },
                [onError](const std::string &error) {
                    onError(error);
                }
            );
        },
        onInvalidCredentials,
        onError
    );
}

void UserService::logoutUser(
    const std::string &tokenId,
    std::function<void()> onSuccess,
    std::function<void()> onNotFound,
    std::function<void(const std::string &error)> onError
) 
{
    SessionRepository::revoke(tokenId, onSuccess, onNotFound, onError);
}

void UserService::validateToken(
    const std::string &token,
    std::function<void(int userId)> onValid,
    std::function<void(const std::string &reason)> onInvalid,
    std::function<void(const std::string &error)> onError
) 
{
    try 
    {
        using namespace jwt::params;
        
        std::error_code ec;
        auto decoded = jwt::decode(
            token,
            algorithms({AuthConfig::JWT_ALGORITHM()}),
            ec,
            secret(AuthConfig::JWT_SECRET()),
            verify(true)
        );

        if (ec) 
        {
            onInvalid("Invalid token: " + ec.message());
            return;
        }

        // Check session is still active in DB
        SessionRepository::findByTokenId(
            token,
            [onValid](int userId) {
                onValid(userId);
            },
            [onInvalid]() {
                onInvalid("Token revoked or expired");
            },
            [onError](const std::string &error) {
                onError(error);
            }
        );

    } 
    catch (const std::exception &e) 
    {
        onInvalid(std::string("Invalid token: ") + e.what());
    }
}