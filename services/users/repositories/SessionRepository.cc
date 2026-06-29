#include "SessionRepository.h"
#include "../../shared/DB_Repository.h"

void SessionRepository::insert(
    int userId,
    const std::string &tokenId,
    const std::string &ip,
    std::function<void()> onSuccess,
    std::function<void(const std::string &error)> onError
) {
    DB_Repository::getInstance().run_update_query_params(
        "INSERT INTO user_sessions (user_id, token_id, ip, expires_at) "
        "VALUES ($1, $2, $3, NOW() + INTERVAL '24 hours')",
        [onSuccess](size_t rowsAffected) {
            onSuccess();
        },
        [onError](const std::string &error) {
            onError(error);
        },
        userId, tokenId, ip
    );
}

void SessionRepository::revoke(
    const std::string &tokenId,
    std::function<void()> onSuccess,
    std::function<void()> onNotFound,
    std::function<void(const std::string &error)> onError
) {
    DB_Repository::getInstance().run_update_query_params(
        "UPDATE user_sessions SET status = 'revoked' "
        "WHERE token_id = $1 AND status = 'active'",
        [onSuccess, onNotFound](size_t rowsAffected) {
            if (rowsAffected == 0) {
                onNotFound();
            } else {
                onSuccess();
            }
        },
        [onError](const std::string &error) {
            onError(error);
        },
        tokenId
    );
}

void SessionRepository::findByTokenId(
    const std::string &tokenId,
    std::function<void(int userId)> onFound,
    std::function<void()> onNotFound,
    std::function<void(const std::string &error)> onError
) {
    DB_Repository::getInstance().run_query_params(
        "SELECT user_id FROM user_sessions "
        "WHERE token_id = $1 AND status = 'active' AND expires_at > NOW()",
        [onFound, onNotFound](const drogon::orm::Result &result) {
            if (result.empty()) {
                onNotFound();
            } else {
                int userId = result[0]["user_id"].as<int>();
                onFound(userId);
            }
        },
        [onError](const std::string &error) {
            onError(error);
        },
        tokenId
    );
}