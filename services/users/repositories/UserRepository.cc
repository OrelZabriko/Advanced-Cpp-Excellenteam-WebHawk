#include "UserRepository.h"
#include "../../shared/DB_Repository.h"

void UserRepository::findByEmail(
    const std::string &email,
    std::function<void(int id, const std::string &passwordHash)> onFound,
    std::function<void()> onNotFound,
    std::function<void(const std::string &error)> onError
) 
{
    DB_Repository::getInstance().run_query_params(
        "SELECT id, password_hash FROM users WHERE email = $1",
        [onFound, onNotFound](const drogon::orm::Result &result) {
            if (result.empty()) 
            {
                onNotFound();
            } 
            else 
            {
                int id = result[0]["id"].as<int>();
                std::string passwordHash = result[0]["password_hash"].as<std::string>();
                onFound(id, passwordHash);
            }
        },
        [onError](const std::string &error) {
            onError(error);
        },
        email
    );
}

void UserRepository::insert(
    const std::string &email,
    const std::string &passwordHash,
    std::function<void()> onSuccess,
    std::function<void()> onDuplicate,
    std::function<void(const std::string &error)> onError
) {
    DB_Repository::getInstance().run_update_query_params(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
        [onSuccess](size_t rowsAffected) {
            onSuccess();
        },
        [onDuplicate, onError](const std::string &error) {
            if (error.find("duplicate key") != std::string::npos) 
            {
                onDuplicate();
            } 
            else 
            {
                onError(error);
            }
        },
        email, passwordHash
    );
}