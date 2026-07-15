#pragma once

#include <string>
#include <functional>
#include <drogon/drogon.h>

class SessionRepository 
{
public:
    // Insert a new session after login
    static void insert(
        int userId,
        const std::string &tokenId,
        const std::string &ip,
        std::function<void()> onSuccess,
        std::function<void(const std::string &error)> onError
    );

    // Revoke a session on logout
    static void revoke(
        const std::string &tokenId,
        std::function<void()> onSuccess,
        std::function<void()> onNotFound,
        std::function<void(const std::string &error)> onError
    );

    // checks if a session is active
    static void findByTokenId(
        const std::string &tokenId,
        std::function<void(int userId)> onFound,
        std::function<void()> onNotFound,
        std::function<void(const std::string &error)> onError
    );
};