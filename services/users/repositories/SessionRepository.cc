#include "SessionRepository.h"
#include "../../shared/DB_Repository.h"

void SessionRepository::insert(
    int userId,
    const std::string &tokenId,
    const std::string &ip,
    std::function<void()> onSuccess,
    std::function<void(const std::string &error)> onError
) {
    std::string sql = 
        "INSERT INTO user_sessions (user_id, token_id, ip, expires_at) "
        "VALUES (" + std::to_string(userId) + ", '" + tokenId + "', '" + ip + 
        "', NOW() + INTERVAL '24 hours')";

    DB_Repository::getInstance().run_update_query(
        sql,
        [onSuccess](size_t rowsAffected) {
            onSuccess();
        },
        [onError](const std::string &error) {
            onError(error);
        }
    );
}

void SessionRepository::revoke(
    const std::string &tokenId,
    std::function<void()> onSuccess,
    std::function<void()> onNotFound,
    std::function<void(const std::string &error)> onError
) {
    std::string sql = 
        "UPDATE user_sessions SET status = 'revoked' "
        "WHERE token_id = '" + tokenId + "' AND status = 'active'";

    DB_Repository::getInstance().run_update_query(
        sql,
        [onSuccess, onNotFound](size_t rowsAffected) {
            if (rowsAffected == 0) {
                onNotFound();
            } else {
                onSuccess();
            }
        },
        [onError](const std::string &error) {
            onError(error);
        }
    );
}